/*
 * FUSE: Filesystem in Userspace
 * Copyright (C) 2025  Bernd Schubert <bschubert@ddn.com>
 *
 * Implementation of (most of) FUSE-over-io-uring.
 *
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file COPYING.LIB
 */

#define _GNU_SOURCE

#include "fuse_i.h"
#include "fuse_kernel.h"
#include "fuse_uring_i.h"

#include <stdlib.h>
#include <liburing.h>
#include <sys/sysinfo.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <numa.h>
#include <pthread.h>
#include <stdio.h>
#include <linux/sched.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <limits.h>

/* Size of command data area in SQE when IORING_SETUP_SQE128 is used */
#define FUSE_URING_MAX_SQE128_CMD_DATA 80

struct fuse_ring_ent {
	struct fuse_ring_queue *ring_queue; /* back pointer */
	struct fuse_req req;

	struct fuse_uring_req_header *req_header;
	void *op_payload;
	size_t req_payload_sz;

	/* commit id of a fuse request */
	uint64_t req_commit_id;

	/* header and payload */
	struct iovec iov[2];
};

struct fuse_ring_queue {
	/* back pointer */
	struct fuse_ring_pool *ring_pool;
	int qid;
	int numa_node;
	pthread_t tid;
	int eventfd;
	size_t req_header_sz;
	struct io_uring ring;

	/* size depends on queue depth */
	struct fuse_ring_ent ent[];
};

/**
 * Main fuse_ring structure, holds all fuse-ring data
 */
struct fuse_ring_pool {
	struct fuse_session *se;

	/* number of queues */
	size_t nr_queues;

	/* number of per queue entries */
	size_t queue_depth;

	/* number of queues to use */
	size_t nr_queues_to_use;

	/* optional mask where to start ring queues/threads on */
	cpu_set_t *cpu_set;

	/* max payload size for fuse requests*/
	size_t max_req_payload_sz;

	/* size of a single queue */
	size_t queue_mem_size;

	/* pointer to the first queue */
	struct fuse_ring_queue *queues;
};

/* Helper function to convert hex character to value */
static unsigned int hex_to_value(char hex_char)
{
	if (hex_char >= '0' && hex_char <= '9')
		return hex_char - '0';
	else if (hex_char >= 'a' && hex_char <= 'f')
		return hex_char - 'a' + 10;
	else if (hex_char >= 'A' && hex_char <= 'F')
		return hex_char - 'A' + 10;
	else
		return 0; /* Invalid character */
}

/* Number of bits in a hexadecimal digit */
#define BITS_PER_HEX_DIGIT 4

static int parse_cpu_token_hex(const char *token, int nr_cpus,
			       cpu_set_t *cpu_set)
{
	const char *hex_string = token + 2; /* Skip "0x" prefix */
	size_t str_len = strlen(hex_string);

	/* Process hex string from right to left, setting bits in cpu_set */
	for (int pos = str_len - 1; pos >= 0; pos--) {
		unsigned int value = hex_to_value(hex_string[pos]);

		/* Example: In "0xA5", str_len=2:
		 * For digit '5' (pos=1): cpu_base = (2-1-1)*4 = 0 (CPUs 0-3)
		 * For digit 'A' (pos=0): cpu_base = (2-1-0)*4 = 4 (CPUs 4-7)
		 */
		int cpu_base = (str_len - 1 - pos) * BITS_PER_HEX_DIGIT;

		/* Set bits for this digit */
		for (int bit = 0; bit < BITS_PER_HEX_DIGIT; bit++) {
			int cpu = cpu_base + bit;

			if (value & (1 << bit)) {
				if (cpu >= nr_cpus) {
					/* Found a bit set for CPU that's out of range */
					fuse_log(
						FUSE_LOG_ERR,
						"CPU mask contains CPU %d which exceeds maximum CPU %d\n",
						cpu, nr_cpus - 1);
					return -EINVAL;
				}

				/* Set this CPU in the mask */
				CPU_SET_S(cpu, CPU_ALLOC_SIZE(nr_cpus),
					  cpu_set);
			}
		}
	}

	return 0;
}

/**
 * Parse a single CPU number or range
 * @param token String containing a single CPU number or range
 * @param nr_cpus Maximum number of CPUs to consider
 * @param cpu_set CPU set to update
 * @return 0 on success, negative error code on failure
 */
static int parse_cpu_token(const char *token, int nr_cpus, cpu_set_t *cpu_set)
{
	char *range_str;
	long start, end, cpu;
	char *token_copy = strdup(token);
	int err;

	if (!token_copy)
		return -ENOMEM;

	/* Check if it's a range (contains a dash) */
	range_str = strchr(token_copy, '-');
	if (range_str) {
		*range_str = '\0';
		range_str++;

		/* Parse start of range (supports hex with 0x prefix) */
		int ret = _libfuse_strtol(token_copy, &start, 0);
		if (ret != 0) {
			fuse_log(FUSE_LOG_ERR,
				 "Failed to parse CPU range start: %s\n",
				 token_copy);
			err = -EINVAL;
			goto out;
		}

		/* Parse end of range (supports hex with 0x prefix) */
		ret = _libfuse_strtol(range_str, &end, 0);
		if (ret != 0 || end < 0 || end >= nr_cpus || end < start) {
			fuse_log(FUSE_LOG_ERR,
				 "Failed to parse CPU range end: %s\n",
				 range_str);
			err = -EINVAL;
			goto out;
		}

		/* Set all CPUs in the range */
		for (cpu = start; cpu <= end; cpu++) {
			CPU_SET_S(cpu, CPU_ALLOC_SIZE(nr_cpus), cpu_set);
		}
	} else {
		/* Single CPU number (supports hex with 0x prefix) */
		int ret = _libfuse_strtol(token_copy, &cpu, 0);
		if (ret != 0 || cpu < 0 || cpu >= nr_cpus) {
			fuse_log(FUSE_LOG_ERR,
				 "Failed to parse CPU number: %s\n",
				 token_copy);
			err = -EINVAL;
			goto out;
		}

		CPU_SET_S(cpu, CPU_ALLOC_SIZE(nr_cpus), cpu_set);
	}

	err = 0;
out:
	free(token_copy);
	return err;
}

/**
 * Parse a comma-separated list of CPU numbers or ranges, like "1,3,5-7,10-12"
 * @param mask_str String representation of the CPU list
 * @param nr_cpus Maximum number of CPUs to consider
 * @param cpu_set CPU set to update
 * @return 0 on success, negative error code on failure
 */
static int parse_cpu_mask_list(const char *mask_str, int nr_cpus,
			       cpu_set_t *cpu_set)
{
	char *str, *ptr, *token, *saveptr = NULL;
	int err = 0;

	/* Make a copy of the mask string for tokenization */
	str = strdup(mask_str);
	if (!str)
		return -ENOMEM;

	ptr = str;

	/* Parse comma-separated values */
	token = strtok_r(ptr, ":", &saveptr);
	while (token) {
		if (parse_cpu_token(token, nr_cpus, cpu_set) < 0) {
			fuse_log(FUSE_LOG_ERR,
				 "Failed to parse CPU token: %s\n", token);
			err = -EINVAL;
			break;
		}
		token = strtok_r(NULL, ",", &saveptr);
	}

	free(str);
	return err;
}

/**
 * Parse a CPU mask string into a CPU set
 * @param mask_str String representation of the CPU mask
 * @param out_mask Pointer to store the allocated CPU set
 * @param out_nr_cpus Pointer to store the number of CPUs in the set
 * @return 0 on success, negative error code on failure
 */
static int parse_cpu_mask(const char *mask_str, cpu_set_t **out_mask,
			  size_t *out_nr_cpus)
{
	cpu_set_t *cpu_set;
	int nr_cpus = get_nprocs_conf();
	int count = 0;
	int err;

	if (!mask_str || !*mask_str)
		return -EINVAL;

	cpu_set = CPU_ALLOC(nr_cpus);
	if (!cpu_set)
		return -ENOMEM;

	CPU_ZERO_S(CPU_ALLOC_SIZE(nr_cpus), cpu_set);

	/* Check if it's a hex mask (starts with 0x) */
	if (strncmp(mask_str, "0x", 2) == 0) {
		err = parse_cpu_token_hex(mask_str, nr_cpus, cpu_set);
		if (err != 0)
			goto parse_error;
	} else {
		err = parse_cpu_mask_list(mask_str, nr_cpus, cpu_set);
		if (err != 0)
			goto parse_error;
	}

	/* Count the number of set bits to ensure at least one CPU is specified */
	for (int idx = 0; idx < nr_cpus; idx++) {
		if (CPU_ISSET(idx, cpu_set))
			count++;
	}

	if (count == 0) {
		fuse_log(FUSE_LOG_ERR, "No CPUs specified in mask\n");
		err = -EINVAL;
		goto parse_error;
	}

	*out_mask = cpu_set;
	*out_nr_cpus = count;
	return 0;

parse_error:
	free(cpu_set);
	return err;
}

static size_t
fuse_ring_queue_size(const size_t q_depth)
{
	const size_t req_size = sizeof(struct fuse_ring_ent) * q_depth;

	return sizeof(struct fuse_ring_queue) + req_size;
}

static struct fuse_ring_queue *
fuse_uring_get_queue(struct fuse_ring_pool *fuse_ring, int qid)
{
	void *ptr =
		((char *)fuse_ring->queues) + (qid * fuse_ring->queue_mem_size);

	return ptr;
}

/**
 * return a pointer to the 80B area
 */
static void *fuse_uring_get_sqe_cmd(struct io_uring_sqe *sqe)
{
	return (void *)&sqe->cmd[0];
}

static void fuse_uring_sqe_set_req_data(struct fuse_uring_cmd_req *req,
					const unsigned int qid,
					const unsigned int commit_id)
{
	req->qid = qid;
	req->commit_id = commit_id;
	req->flags = 0;
}

static void
fuse_uring_sqe_prepare(struct io_uring_sqe *sqe, struct fuse_ring_ent *req,
		       __u32 cmd_op)
{
	/* These fields should be written once, never change */
	sqe->opcode = IORING_OP_URING_CMD;

	/*
	 * IOSQE_FIXED_FILE: fd is the index to the fd *array*
	 * given to io_uring_register_files()
	 */
	sqe->flags = IOSQE_FIXED_FILE;
	sqe->fd = 0;

	sqe->rw_flags = 0;
	sqe->ioprio = 0;
	sqe->off = 0;

	io_uring_sqe_set_data(sqe, req);

	sqe->cmd_op = cmd_op;
	sqe->__pad1 = 0;
}

static int fuse_uring_commit_sqe(struct fuse_ring_pool *ring_pool,
				 struct fuse_ring_queue *queue,
				 struct fuse_ring_ent *ring_ent)
{
	struct fuse_session *se = ring_pool->se;
	struct fuse_uring_req_header *rrh = ring_ent->req_header;
	struct fuse_out_header *out = (struct fuse_out_header *)&rrh->in_out;
	struct fuse_uring_ent_in_out *ent_in_out =
		(struct fuse_uring_ent_in_out *)&rrh->ring_ent_in_out;
	struct io_uring_sqe *sqe = io_uring_get_sqe(&queue->ring);

	if (sqe == NULL) {
		/* This is an impossible condition, unless there is a bug.
		 * The kernel sent back an SQEs, which is assigned to a request.
		 * There is no way to get out of SQEs, as the number of
		 * SQEs matches the number tof requests.
		 */

		se->error = -EIO;
		fuse_log(FUSE_LOG_ERR, "Failed to get a ring SQEs\n");

		return -EIO;
	}

	fuse_uring_sqe_prepare(sqe, ring_ent,
			       FUSE_IO_URING_CMD_COMMIT_AND_FETCH);

	fuse_uring_sqe_set_req_data(fuse_uring_get_sqe_cmd(sqe), queue->qid,
				    ring_ent->req_commit_id);

	if (se->debug) {
		fuse_log(FUSE_LOG_DEBUG, "    unique: %llu, result=%d\n",
			 out->unique, ent_in_out->payload_sz);
	}

	/* XXX: This needs to be a ring config option */
	io_uring_submit(&queue->ring);

	return 0;
}

int send_reply_uring(fuse_req_t req, int error, const void *arg, size_t argsize)
{
	int res;
	struct fuse_ring_ent *ring_ent =
		container_of(req, struct fuse_ring_ent, req);
	struct fuse_uring_req_header *rrh = ring_ent->req_header;
	struct fuse_out_header *out = (struct fuse_out_header *)&rrh->in_out;
	struct fuse_uring_ent_in_out *ent_in_out =
		(struct fuse_uring_ent_in_out *)&rrh->ring_ent_in_out;

	struct fuse_ring_queue *queue = ring_ent->ring_queue;
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	size_t max_payload_sz = ring_pool->max_req_payload_sz;

	if (argsize > max_payload_sz) {
		fuse_log(FUSE_LOG_ERR, "argsize %zu exceeds buffer size %zu",
			 argsize, max_payload_sz);
		error = -EINVAL;
	} else if (argsize) {
		memcpy(ring_ent->op_payload, arg, argsize);
	}
	ent_in_out->payload_sz = argsize;

	out->error  = error;
	out->unique = req->unique;

	res = fuse_uring_commit_sqe(ring_pool, queue, ring_ent);

	fuse_free_req(req);

	return res;
}

int fuse_reply_data_uring(fuse_req_t req, struct fuse_bufvec *bufv,
		    enum fuse_buf_copy_flags flags)
{
	struct fuse_ring_ent *ring_ent =
		container_of(req, struct fuse_ring_ent, req);

	struct fuse_ring_queue *queue = ring_ent->ring_queue;
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	struct fuse_uring_req_header *rrh = ring_ent->req_header;
	struct fuse_out_header *out = (struct fuse_out_header *)&rrh->in_out;
	struct fuse_uring_ent_in_out *ent_in_out =
		(struct fuse_uring_ent_in_out *)&rrh->ring_ent_in_out;
	size_t max_payload_sz = ring_ent->req_payload_sz;
	struct fuse_bufvec dest_vec = FUSE_BUFVEC_INIT(max_payload_sz);
	int res;

	dest_vec.buf[0].mem = ring_ent->op_payload;
	dest_vec.buf[0].size = max_payload_sz;

	res = fuse_buf_copy(&dest_vec, bufv, flags);

	out->error  = res < 0 ? res : 0;
	out->unique = req->unique;

	ent_in_out->payload_sz = res > 0 ? res : 0;

	res = fuse_uring_commit_sqe(ring_pool, queue, ring_ent);

	fuse_free_req(req);

	return res;
}

/**
 * Copy the iov into the ring buffer and submit and commit/fetch sqe
 */
int fuse_send_msg_uring(fuse_req_t req, struct iovec *iov, int count)
{
	struct fuse_ring_ent *ring_ent =
		container_of(req, struct fuse_ring_ent, req);

	struct fuse_ring_queue *queue = ring_ent->ring_queue;
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	struct fuse_uring_req_header *rrh = ring_ent->req_header;
	struct fuse_out_header *out = (struct fuse_out_header *)&rrh->in_out;
	struct fuse_uring_ent_in_out *ent_in_out =
		(struct fuse_uring_ent_in_out *)&rrh->ring_ent_in_out;
	size_t max_buf = ring_pool->max_req_payload_sz;
	size_t len = 0;
	int res = 0;

	/* copy iov into the payload, idx=0 is the header section */
	for (int idx = 1; idx < count; idx++) {
		struct iovec *cur = &iov[idx];

		if (len + cur->iov_len > max_buf) {
			fuse_log(FUSE_LOG_ERR,
				 "iov[%d] exceeds buffer size %zu",
				 idx, max_buf);
			res = -EINVAL; /* Gracefully handle this? */
			break;
		}

		memcpy(ring_ent->op_payload + len, cur->iov_base, cur->iov_len);
		len += cur->iov_len;
	}

	ent_in_out->payload_sz = len;

	out->error  = res;
	out->unique = req->unique;
	out->len = len;

	return fuse_uring_commit_sqe(ring_pool, queue, ring_ent);
}

static int fuse_queue_setup_io_uring(struct io_uring *ring, size_t qid,
				     size_t depth, int fd, int evfd)
{
	int rc;
	struct io_uring_params params = {0};
	int files[2] = { fd, evfd };

	depth += 1; /* for the eventfd poll SQE */

	params.flags = IORING_SETUP_SQE128;

	/* Avoid cq overflow */
	params.flags |= IORING_SETUP_CQSIZE;
	params.cq_entries = depth * 2;

	/* These flags should help to increase performance, but actually
	 * make it a bit slower - reason should get investigated.
	 */
	if (0) {
		/* Has the main slow down effect */
		params.flags |= IORING_SETUP_SINGLE_ISSUER;

		// params.flags |= IORING_SETUP_DEFER_TASKRUN;
		params.flags |= IORING_SETUP_TASKRUN_FLAG;

		/* Second main effect to make it slower */
		params.flags |= IORING_SETUP_COOP_TASKRUN;
	}

	rc = io_uring_queue_init_params(depth, ring, &params);
	if (rc != 0) {
		fuse_log(FUSE_LOG_ERR, "Failed to setup qid %zu: %d (%s)\n",
			 qid, rc, strerror(-rc));
		return rc;
	}

	rc = io_uring_register_files(ring, files, 1);
	if (rc != 0) {
		rc = -errno;
		fuse_log(FUSE_LOG_ERR,
			 "Failed to register files for ring idx %zu: %s",
			 qid, strerror(errno));
		return rc;
	}

	return 0;
}

static void fuse_session_destruct_uring(struct fuse_ring_pool *fuse_ring)
{
	for (size_t qid = 0; qid < fuse_ring->nr_queues; qid++) {
		struct fuse_ring_queue *queue =
			fuse_uring_get_queue(fuse_ring, qid);

		if (queue->tid != 0) {
			uint64_t value = 1ULL;
			int rc;

			rc = write(queue->eventfd, &value, sizeof(value));
			if (rc != sizeof(value))
				fprintf(stderr,
					"Wrote to eventfd=%d err=%s: rc=%d\n",
					queue->eventfd, strerror(errno), rc);
			pthread_cancel(queue->tid);
			pthread_join(queue->tid, NULL);
			queue->tid = 0;
		}

		if (queue->eventfd >= 0) {
			close(queue->eventfd);
			queue->eventfd = -1;
		}

		if (queue->ring.ring_fd != -1)
			io_uring_queue_exit(&queue->ring);

		for (size_t idx = 0; idx < fuse_ring->queue_depth; idx++) {
			struct fuse_ring_ent *ent = &queue->ent[idx];

			numa_free(ent->op_payload, ent->req_payload_sz);
			numa_free(ent->req_header, queue->req_header_sz);
		}
	}

	CPU_FREE(fuse_ring->cpu_set);
	free(fuse_ring->queues);
	free(fuse_ring);
}

static int fuse_uring_prepare_fetch_sqes(struct fuse_ring_queue *queue)
{
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	unsigned int sq_ready;
	struct io_uring_sqe *sqe;

	for (size_t idx = 0; idx < ring_pool->queue_depth; idx++) {
		struct fuse_ring_ent *ent = &queue->ent[idx];

		sqe = io_uring_get_sqe(&queue->ring);
		if (sqe == NULL) {
			/* All SQEs are idle here - no good reason this
			 * could fail
			 */

			fuse_log(FUSE_LOG_ERR, "Failed to get all ring SQEs");
			return -EIO;
		}

		fuse_uring_sqe_prepare(sqe, ent, FUSE_IO_URING_CMD_REGISTER);

		/* only needed for fetch */
		ent->iov[0].iov_base = ent->req_header;
		ent->iov[0].iov_len = queue->req_header_sz;

		ent->iov[1].iov_base = ent->op_payload;
		ent->iov[1].iov_len = ent->req_payload_sz;

		sqe->addr = (uint64_t)(ent->iov);
		sqe->len = 2;

		/* this is a fetch, kernel does not read commit id */
		fuse_uring_sqe_set_req_data(fuse_uring_get_sqe_cmd(sqe),
					    queue->qid, 0);
	}

	sq_ready = io_uring_sq_ready(&queue->ring);
	if (sq_ready != ring_pool->queue_depth) {
		fuse_log(FUSE_LOG_ERR,
			 "SQE ready mismatch, expected %d got %d\n",
			 ring_pool->queue_depth, sq_ready);
		return -EINVAL;
	}

	/* Poll SQE for the eventfd to wake up on teardown */
	sqe = io_uring_get_sqe(&queue->ring);
	if (sqe == NULL) {
		fuse_log(FUSE_LOG_ERR, "Failed to get eventfd SQE");
		return -EIO;
	}

	io_uring_prep_poll_add(sqe, queue->eventfd, POLLIN);
	io_uring_sqe_set_data(sqe, (void *)(uintptr_t)queue->eventfd);

	io_uring_submit(&queue->ring);

	return 0;
}

/**
 * Create a CPU set that distributes queues evenly across NUMA nodes
 *
 * @param nr_queues Number of queues to distribute
 * @return CPU set with selected CPUs, or NULL on error
 */
static cpu_set_t *fuse_create_cpu_set(size_t nr_queues)
{
	cpu_set_t *cpu_set;
	int nr_cpus = get_nprocs_conf();
	int nr_nodes = numa_num_configured_nodes();
	int *cpus_per_node = NULL;
	int *queues_per_node = NULL;
	int idx, node, err = 0;

	cpu_set = CPU_ALLOC(nr_cpus);
	if (!cpu_set) {
		fuse_log(FUSE_LOG_ERR, "Failed to allocate cpu_set\n");
		return NULL;
	}

	/* Initialize the CPU set with the proper size */
	CPU_ZERO_S(CPU_ALLOC_SIZE(nr_cpus), cpu_set);

	/* Set all cores by default */
	for (idx = 0; idx < nr_cpus; idx++)
		CPU_SET_S(idx, CPU_ALLOC_SIZE(nr_cpus), cpu_set);

	/* If nr_queues equals nr_cpus, use all CPUs */
	if (nr_queues >= nr_cpus)
		return cpu_set;

	CPU_ZERO_S(CPU_ALLOC_SIZE(nr_cpus), cpu_set);

	/* Count CPUs per NUMA node */
	cpus_per_node = calloc(nr_nodes, sizeof(*cpus_per_node));
	if (!cpus_per_node) {
		fuse_log(FUSE_LOG_ERR, "Failed to allocate cpus_per_node\n");
		err = -ENOMEM;
		goto out;
	}
	/* Count CPUs per node */
	for (idx = 0; idx < nr_cpus; idx++)
		cpus_per_node[numa_node_of_cpu(idx)]++;

	queues_per_node = calloc(nr_nodes, sizeof(*queues_per_node));
	if (!queues_per_node) {
		fuse_log(FUSE_LOG_ERR, "Failed to allocate queues_per_node\n");
		err = -ENOMEM;
		goto out;
	}

	/* Distribute queues across NUMA nodes */
	node = 0;
	for (idx = 0; idx < nr_queues; idx++) {
retry:
		if (cpus_per_node[node] == 0) {
			node = (node + 1) % nr_nodes;
			goto retry;
		}

		cpus_per_node[node]--;
		queues_per_node[node]++;
	}

	/* Select CPUs for the queues according to NUMA distribution */
	for (idx = 0; idx < nr_cpus; idx++) {
		node = numa_node_of_cpu(idx);

		if (node < 0 || node >= nr_nodes) {
			fuse_log(FUSE_LOG_ERR,
				 "Failed to get NUMA node for CPU %d\n", idx);
			err = -EINVAL;
			goto out;
		}

		if (queues_per_node[node] > 0) {
			CPU_SET_S(idx, CPU_ALLOC_SIZE(nr_cpus), cpu_set);
			queues_per_node[node]--;
		}
	}

out:
	if (err) {
		CPU_FREE(cpu_set);
		cpu_set = NULL;
	}

	free(queues_per_node);
	free(cpus_per_node);
	return cpu_set;
}

static struct fuse_ring_pool *fuse_create_ring(struct fuse_session *se)
{
	struct fuse_ring_pool *fuse_ring = NULL;
	size_t nr_procs = get_nprocs_conf();
	size_t nr_queues = nr_procs;
	size_t payload_sz = se->bufsize - FUSE_BUFFER_HEADER_SIZE;
	size_t queue_sz;
	cpu_set_t *cpu_set = NULL;

	if (se->uring.nr_queues != UINT_MAX)
		nr_queues = se->uring.nr_queues;

	if (se->uring.q_mask) {
		int err;

		err = parse_cpu_mask(se->uring.q_mask, &cpu_set, &nr_queues);
		if (err != 0) {
			fuse_log(FUSE_LOG_ERR,
				 "Failed to parse q_mask: %s: %s\n",
				 se->uring.q_mask, strerror(-err));
			goto err;
		}
	} else {
		cpu_set = fuse_create_cpu_set(nr_queues);
		if (!cpu_set) {
			fuse_log(FUSE_LOG_ERR, "Failed to create CPU set\n");
			goto err;
		}
	}

	if (se->debug)
		fuse_log(FUSE_LOG_DEBUG,
			 "starting io-uring nr_queues=%zu, q-depth=%d\n",
			 nr_queues, se->uring.q_depth);

	fuse_ring = calloc(1, sizeof(*fuse_ring));
	if (fuse_ring == NULL) {
		fuse_log(FUSE_LOG_ERR, "Allocating the ring failed\n");
		goto err;
	}

	queue_sz = fuse_ring_queue_size(se->uring.q_depth);
	fuse_ring->queues = calloc(1, queue_sz * nr_queues);
	if (fuse_ring->queues == NULL) {
		fuse_log(FUSE_LOG_ERR, "Allocating the queues failed\n");
		goto err;
	}

	fuse_ring->se = se;
	fuse_ring->nr_queues = nr_queues;
	fuse_ring->queue_depth = se->uring.q_depth;
	fuse_ring->max_req_payload_sz = payload_sz;
	fuse_ring->queue_mem_size = queue_sz;
	fuse_ring->cpu_set = cpu_set;

	/*
	 * very basic queue initialization, that cannot fail and will
	 * allow easy cleanup if something (like mmap) fails in the middle
	 * below
	 */
	int qid = 0;
	for (size_t cpu = 0; cpu < nr_procs; cpu++) {
		/* Skip this queue if its CPU is not in the CPU set */
		if (!CPU_ISSET(cpu, cpu_set))
			continue;

		struct fuse_ring_queue *queue =
			fuse_uring_get_queue(fuse_ring, qid);

		queue->ring.ring_fd = -1;
		queue->numa_node = numa_node_of_cpu(cpu);
		queue->qid = qid;
		queue->ring_pool = fuse_ring;

		qid++;
	}

	return fuse_ring;

err:
	if (cpu_set)
		CPU_FREE(cpu_set);

	if (fuse_ring)
		fuse_session_destruct_uring(fuse_ring);

	return NULL;
}

static void fuse_uring_handle_cqe(struct fuse_ring_queue *queue,
				  struct io_uring_cqe *cqe)
{
	struct fuse_ring_ent *ent = io_uring_cqe_get_data(cqe);

	if (!ent) {
		fuse_log(FUSE_LOG_ERR,
			 "cqe=%p io_uring_cqe_get_data returned NULL\n", cqe);
		return;
	}

	struct fuse_req *req = &ent->req;
	struct fuse_ring_pool *fuse_ring = queue->ring_pool;
	struct fuse_uring_req_header *rrh = ent->req_header;

	struct fuse_in_header *in = (struct fuse_in_header *)&rrh->in_out;
	struct fuse_uring_ent_in_out *ent_in_out = &rrh->ring_ent_in_out;

	ent->req_commit_id = ent_in_out->commit_id;
	if (unlikely(ent->req_commit_id == 0)) {
		/*
		 * If this happens kernel will not find the response - it will
		 * be stuck forever - better to abort immediately.
		 */
		fuse_log(FUSE_LOG_ERR, "Received invalid commit_id=0\n");
		abort();
	}

	req->is_uring = true;
	req->ref_cnt++;
	req->ch = NULL; /* not needed for uring */

	fuse_session_process_uring_cqe(fuse_ring->se, req, in, &rrh->op_in,
				       ent->op_payload, ent_in_out->payload_sz);
}

static int fuse_uring_queue_handle_cqes(struct fuse_ring_queue *queue)
{
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	struct fuse_session *se = ring_pool->se;
	size_t num_completed = 0;
	struct io_uring_cqe *cqe;
	unsigned int head;
	int ret = 0;

	io_uring_for_each_cqe(&queue->ring, head, cqe) {
		int err = 0;

		num_completed++;

		err = cqe->res;
		if (err != 0) {
			if (err > 0 && ((uintptr_t)io_uring_cqe_get_data(cqe) ==
					(unsigned int)queue->eventfd)) {
				/* teardown from eventfd */
				return -ENOTCONN;
			}

			// XXX: Needs rate limited logs, otherwise log spam
			//fuse_log(FUSE_LOG_ERR, "cqe res: %d\n", cqe->res);

			/* -ENOTCONN is ok on umount  */
			if (err != -EINTR && err != -EOPNOTSUPP &&
			    err != -EAGAIN && err != -ENOTCONN) {
				se->error = cqe->res;

				/* return first error */
				if (ret == 0)
					ret = err;
			}

		} else {
			fuse_uring_handle_cqe(queue, cqe);
		}
	}

	if (num_completed)
		io_uring_cq_advance(&queue->ring, num_completed);

	return ret == 0 ? 0 : num_completed;
}

/**
 * In per-core-queue configuration we have thread per core - the thread
 * to that core
 */
static void fuse_uring_set_thread_core(int qid)
{
	cpu_set_t mask;
	int rc;

	CPU_ZERO(&mask);
	CPU_SET(qid, &mask);
	rc = sched_setaffinity(0, sizeof(cpu_set_t), &mask);
	if (rc != 0)
		fuse_log(FUSE_LOG_ERR, "Failed to bind qid=%d to its core: %s\n",
			 qid, strerror(errno));

	if (0) {
		const int policy = SCHED_IDLE;
		const struct sched_param param = {
			.sched_priority = sched_get_priority_min(policy),
		};

		/* Set the lowest possible priority, so that the application
		 * submitting requests is not moved away from the current core.
		 */
		rc = sched_setscheduler(0, policy, &param);
		if (rc != 0)
			fuse_log(FUSE_LOG_ERR, "Failed to set scheduler: %s\n",
				strerror(errno));
	}
}

/*
 * @return negative error code or io-uring file descriptor
 */
static int fuse_uring_init_queue(struct fuse_ring_queue *queue)
{
	struct fuse_ring_pool *ring = queue->ring_pool;
	struct fuse_session *se = ring->se;
	int res;
	size_t page_sz = sysconf(_SC_PAGESIZE);

	queue->eventfd = eventfd(0, EFD_CLOEXEC);
	if (queue->eventfd < 0) {
		res = -errno;
		fuse_log(FUSE_LOG_ERR,
			 "Failed to create eventfd for qid %d: %s\n",
			 queue->qid, strerror(errno));
		return res;
	}

	res = fuse_queue_setup_io_uring(&queue->ring, queue->qid,
					ring->queue_depth, se->fd,
					queue->eventfd);
	if (res != 0) {
		fuse_log(FUSE_LOG_ERR, "qid=%d io_uring init failed\n",
			 queue->qid);
		goto err;
	}

	queue->req_header_sz = ROUND_UP(sizeof(struct fuse_ring_ent),
				       page_sz);

	for (size_t idx = 0; idx < ring->queue_depth; idx++) {
		struct fuse_ring_ent *ring_ent = &queue->ent[idx];
		struct fuse_req *req = &ring_ent->req;

		ring_ent->ring_queue = queue;

		/*
		 * Also allocate the header to have it page aligned, which
		 * is a requirement for page pinning
		 */
		ring_ent->req_header =
			numa_alloc_local(queue->req_header_sz);
		ring_ent->req_payload_sz = ring->max_req_payload_sz;

		ring_ent->op_payload =
			numa_alloc_local(ring_ent->req_payload_sz);

		req->se = se;
		pthread_mutex_init(&req->lock, NULL);
		req->is_uring = true;
		req->ref_cnt = 1;
	}

	res = fuse_uring_prepare_fetch_sqes(queue);
	if (res != 0) {
		fuse_log(
			FUSE_LOG_ERR,
			"Grave fuse-uring error on preparing SQEs, aborting\n");
		se->error = -EIO;
		fuse_session_exit(se);
	}

	return queue->ring.ring_fd;

err:
	close(queue->eventfd);
	return res;
}

static void *fuse_uring_thread(void *arg)
{
	struct fuse_ring_queue *queue = arg;
	struct fuse_ring_pool *ring_pool = queue->ring_pool;
	struct fuse_session *se = ring_pool->se;
	int err;
	char thread_name[16] = { 0 };

	snprintf(thread_name, 16, "fuse-ring-%d", queue->qid);
	thread_name[15] = '\0';
	fuse_set_thread_name(thread_name);

	fuse_uring_set_thread_core(queue->qid);

	err = fuse_uring_init_queue(queue);
	if (err < 0) {
		fuse_log(FUSE_LOG_ERR, "qid=%d queue setup failed\n",
			 queue->qid);
		goto err;
	}

	/* Not using fuse_session_exited(se), as that cannot be inlined */
	while (!atomic_load_explicit(&se->mt_exited, memory_order_relaxed)) {
		io_uring_submit_and_wait(&queue->ring, 1);

		err = fuse_uring_queue_handle_cqes(queue);
		if (err < 0) {
			/*
			 * fuse-over-io-uring is not supported, operation can
			 * continue over /dev/fuse
			 */
			if (err == -EOPNOTSUPP)
				goto ret;
			goto err;
		}
	}

	return NULL;

err:
	fuse_session_exit(se);
ret:
	return NULL;
}

static int fuse_uring_start_ring_threads(struct fuse_ring_pool *ring)
{
	int rc = 0;
	int qid = 0;

	for (size_t cpu = 0; cpu < get_nprocs_conf(); cpu++) {
		/* Skip this queue if its CPU is not in the CPU set */
		if (!CPU_ISSET(cpu, ring->cpu_set))
			continue;

		struct fuse_ring_queue *queue = fuse_uring_get_queue(ring, qid);

		rc = pthread_create(&queue->tid, NULL, fuse_uring_thread, queue);
		if (rc != 0) {
			fuse_log(FUSE_LOG_ERR,
				 "Failed to start thread for qid=%d\n", qid);
			break;
		}

		qid++;
	}

	return rc;
}

static int fuse_uring_sanity_check(struct fuse_session *se)
{
	if (se->uring.q_depth == 0) {
		fuse_log(FUSE_LOG_ERR, "io-uring queue depth must be > 0\n");
		return -EINVAL;
	}

	if (se->uring.nr_queues == 0) {
		fuse_log(FUSE_LOG_ERR,
			 "io-uring number of queues must be > 0\n");
		return -EINVAL;
	}

	if (se->uring.nr_queues != UINT_MAX &&
	    se->uring.nr_queues > get_nprocs_conf()) {
		fuse_log(
			FUSE_LOG_ERR,
			"io-uring number of queues must be <= number of CPUs\n");
		return -EINVAL;
	}

	if (se->uring.q_mask && se->uring.nr_queues != UINT_MAX) {
		fuse_log(
			FUSE_LOG_ERR,
			"io-uring queue mask and number-of queues are mutually exclusive\n");
		return -EINVAL;
	}

	_Static_assert(sizeof(struct fuse_uring_cmd_req) <=
			       FUSE_URING_MAX_SQE128_CMD_DATA,
		       "SQE128_CMD_DATA has 80B cmd data");

	return 0;
}

int fuse_uring_start(struct fuse_session *se)
{
	int err = 0;
	struct fuse_ring_pool *fuse_ring;

	err = fuse_uring_sanity_check(se);
	if (err != 0)
		return err;

	fuse_ring = fuse_create_ring(se);
	if (fuse_ring == NULL) {
		err = -EADDRNOTAVAIL;
		goto out;
	}

	se->uring.pool = fuse_ring;

	err = fuse_uring_start_ring_threads(fuse_ring);
out:
	return err;
}

int fuse_uring_stop(struct fuse_session *se)
{
	struct fuse_ring_pool *ring = se->uring.pool;

	if (ring == NULL)
		return 0;

	fuse_session_destruct_uring(ring);

	return 0;
}
