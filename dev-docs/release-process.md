Release Process
===============

`scripts/release.py` does the work. Run it from a libfuse checkout. Every
command takes `--dry-run`: it prints the exact commands and changes nothing.
3.19.0 stands for the release being cut in every example below.

Step 1 -- prepare the release commit
------------------------------------

* `scripts/release.py prepare 3.19.0`
* Sets the version in `meson.build`.
* Renames the `Unreleased Changes` section of `ChangeLog.rst` to this release.
* Appends every author who is not in `AUTHORS` yet.
* Generates a signing key only when the next release has none, which is a new
  minor or major version. A patch release inherits the keys of its `.0`.
* Leaves one commit, `Released fuse-3.19.0`.
* Offers the `git push` of the branch, and prints the URL of the pull request
  page for it. `--remote` and `--base` pick the two.

Step 2 -- get the pull request merged
-------------------------------------

* Open the pull request at the printed URL, and get it merged. Neither is
  scriptable without `gh`.
* `git checkout master`. `publish` reads the signing keys from the checkout,
  so it releases another branch only from master.
* Pulling master is not needed. `publish` offers the fast-forward itself.

Step 3 -- publish
-----------------

* `scripts/release.py publish`
* Each action is shown with the commands it runs and confirmed on its own:

  * update -- `git pull --ff-only`, when the branch is behind the remote
  * pack -- `git archive`, `doxygen`, `tar -czf`
  * test -- `tar -xzf` into `verify/`, `test/ci-build.sh --name release`
  * tag -- `git tag -s`
  * sign -- `signify-openbsd -S`, then `-V`
  * write -- `fuse-3.19.0-notes.md`, `fuse-3.19.0-announce.txt`
  * push -- `git push origin refs/tags/fuse-3.19.0`
  * publish `doxygen/` in `../libfuse.github.io`

* A no before the tag ends the release with nothing to take back.
* A no to one of the two pushes skips it; the rest still runs.
* Whatever is there already is reused, so an interrupted run can be repeated.
* Released is the branch `--branch` names, the checked-out one by default. The
  version and the ChangeLog are read out of its commit, not out of the
  checkout. Another branch than the checked-out one needs master checked out.
  Every `signify/*.pub` is on master, a release branch only has the ones that
  existed when it forked.
* That branch has to point at what `origin` has it point at, so what is
  released is what everyone else can see.
* `--remote` picks the remote the tag goes to, `--pages-dir` the
  libfuse.github.io checkout, which is cloned when it is not there.
  `--skip-test` leaves the test build out, `--skip-docs` the API
  documentation, `--work-dir` is passed to `test/ci-build.sh`, and `--force`
  packs the tarball again.

Step 4 -- create the GitHub release
-----------------------------------

* Open the URL `publish` printed.
* Title, notes file and the two attachments: `publish` names them.
* GitHub is never written to by the script.

Step 5 -- send the announcement
-------------------------------

* Send `fuse-3.19.0-announce.txt` to fuse-devel@lists.linux.dev.

The tarball
-----------

* `git archive` of the commit: an uncommitted source file builds here and is
  missing for everyone who downloads.
* Extracted tree: every `.gitignore` deleted, `.github` and `.cirrus.yml`
  removed, `doxygen doc/Doxyfile` writes `doc/html`.
* Named after the version the packed `meson.build` declares, so
  `release.py tarball HEAD` and `release.py tarball fuse-3.19.0` agree.
* The extracted tree stays next to the tarball, `doxygen/` is copied from its
  `doc/html`.
* All of it lands in `/var/tmp/fuse-release`, `--output-dir` elsewhere: the
  tree, the tarball, its signature, the notes and the announcement would
  otherwise sit untracked in the checkout, and only `*.gz` is gitignored.

The test build
--------------

* `release.py test fuse-3.19.0.tar.gz` unpacks it into `verify/` next to
  itself and runs `test/ci-build.sh --name release` in there.
* Unpacked rather than built where it was packed: the build has to see what a
  downloader gets, so a file `git archive` leaves out fails the release
  instead of the download.
* `publish` runs it before the tag exists, so a failure costs nothing.
* `test/ci-build.sh` calls `sudo` for its install prefix and the suite takes a
  while -- `--skip-test` when it has already been run.
* `test/ci/prepare-runner.sh` is not part of this. It rewrites
  `kernel.core_pattern`, which a CI runner needs and a workstation must not
  get.

Signing keys
------------

* `signify/fuse-<major>.<minor>.sec` signs every release of that minor and is
  gitignored -- back it up.
* `prepare X.Y.0` generates the keys of `X.<Y+1>` and `<X+1>.0` and commits
  their `.pub`, so this release carries the key of whichever comes next.
* `prepare X.Y.Z` refuses when one of them is gone: it may be published
  already, and a second key of that name is indistinguishable to whoever
  verifies with the first. `--new-key` generates it anyway.
* Expire the keys of old releases, keeping one around just in case.
