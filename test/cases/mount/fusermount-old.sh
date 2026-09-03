#!/usr/bin/env bash
# GROUP: mount quick serial

_fuse_no_mount_needed=1
. "$TEST_LIB/common.sh"

[ "${FUSE_TEST_CI_BUILD:-}" = 1 ] || _notrun "needs test/ci-build.sh"
_require_linux "fusermount3 feature probing"

install_prefix=$(readlink -f -- "$FUSE_TEST_INSTALL_PREFIX") ||
	_fail "cannot resolve the test installation prefix"
case $install_prefix in
/|/usr|/usr/local)
	_fail "refusing installation prefix $install_prefix"
	;;
esac

fusermount3=$install_prefix/bin/fusermount3
fusermount3_real=$(readlink -f -- "$fusermount3") ||
	_fail "cannot resolve installed fusermount3"
case $fusermount3_real in
"$install_prefix"/*) ;;
*) _fail "installed fusermount3 is outside $install_prefix" ;;
esac
[ -f "$fusermount3" ] || _fail "installed fusermount3 is not a file"
[ ! -L "$fusermount3" ] || _fail "installed fusermount3 is a symlink"

unset _fuse_no_mount_needed
_require_fuse
_require_nonroot
[ "${FUSE_URING_ENABLE}" = 0 ] || _notrun "needs the standard transport"
grep -q '^#define HAVE_NEW_MOUNT_API' "$BUILD_DIR/fuse_config.h" ||
	_notrun "new mount API not built"
# ENOSYS puts libfuse on the mount(2) fallback, which never probes the helper.
[ -z "$FUSE_VALGRIND" ] || _notrun "valgrind fails fsopen() with ENOSYS"
_require_prog sudo
sudo -n true >/dev/null 2>&1 || _notrun "needs non-interactive sudo"

fusermount3_moved=$fusermount3.moved
[ ! -e "$fusermount3_moved" ] ||
	_fail "$fusermount3_moved already exists"

# Restore the installed helper after the compatibility test.
restore_fusermount3()
{
	[ ! -e "$fusermount3_moved" ] ||
		sudo -n mv -f -- "$fusermount3_moved" "$fusermount3"
}

sudo -n mv -- "$fusermount3" "$fusermount3_moved"
_at_exit restore_fusermount3

# Quoted delimiter: the wrapper reads FUSERMOUNT_TEST_* from its own
# environment, exported below.
cat >"$TEST_TMP/fusermount3-old" <<'FUSERMOUNT3_OLD'
#!/bin/sh

printf '%s\n' "${1-}" >>"$FUSERMOUNT_TEST_LOG"

case ${1-} in
--help)
	printf '%s\n' 'usage: fusermount3 [options] mountpoint'
	exit 1
	;;
--features)
	printf '%s\n' "fusermount3: unrecognized option '--features'" >&2
	exit 1
	;;
*)
	exec "$FUSERMOUNT_TEST_REAL" "$@"
	;;
esac
FUSERMOUNT3_OLD
sudo -n install -m 0755 -- "$TEST_TMP/fusermount3-old" "$fusermount3"

export FUSERMOUNT_TEST_LOG=$TEST_TMP/fusermount3-arguments
export FUSERMOUNT_TEST_REAL=$fusermount3_moved
: >"$FUSERMOUNT_TEST_LOG"

fuse_mount hello >/dev/null

grep -qx -- '--help' "$FUSERMOUNT_TEST_LOG" ||
	_fail "fusermount3 --help was not invoked"
if grep -qx -- '--features' "$FUSERMOUNT_TEST_LOG"; then
	_fail "fusermount3 --features was invoked"
fi
if grep -q "unrecognized option '--features'" "${FUSE_FS_LOG[0]}"; then
	_fail "fusermount3 printed an invalid-option diagnostic"
fi
