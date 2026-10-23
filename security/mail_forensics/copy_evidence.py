#!/usr/bin/env python3
"""copy_evidence.py SRC DEST -- the copy step of preserve_evidence.sh.

Copies one evidence file in a single pass so nothing can change between
a check and the copy:
  - SRC is opened with O_NOFOLLOW (a symlink swapped in after the shell's
    own checks is refused, not followed) and O_NONBLOCK (a FIFO cannot
    hang the copy); the open file must be a regular file.
  - DEST is created with O_CREAT|O_EXCL|O_NOFOLLOW and mode 0400: an
    existing file or link is never overwritten or followed, and the copy
    is read-only from its first byte.
  - SRC's atime/mtime are carried over (cp -p semantics).
Prints "<sha256 of the bytes copied> <size> <mtime epoch>" on success.
Exit 0 ok, 2 refused or failed (DEST removed only if this run created it
and the copy did not finish).
"""
import hashlib
import os
import stat
import sys


def fail(msg):
    print("copy_evidence: %s" % msg, file=sys.stderr)
    return 2


def main(argv):
    if len(argv) != 3:
        return fail("usage: copy_evidence.py SRC DEST")
    src, dest = argv[1], argv[2]
    try:
        sfd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as e:
        return fail("cannot open source without following links: %s" % e.strerror)
    try:
        st = os.fstat(sfd)
        if not stat.S_ISREG(st.st_mode):
            return fail("source is not a regular file")
        try:
            dfd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        except OSError as e:
            return fail("refusing destination (exists or is a link): %s" % e.strerror)
        done = False
        try:
            h = hashlib.sha256()
            while True:
                chunk = os.read(sfd, 1 << 20)
                if not chunk:
                    break
                h.update(chunk)
                view = memoryview(chunk)
                while view:
                    view = view[os.write(dfd, view):]
            os.fsync(dfd)
            if stat.S_IMODE(os.fstat(dfd).st_mode) != 0o400:
                return fail("destination mode is not 0400")
            done = True
        finally:
            os.close(dfd)
            if not done:
                os.unlink(dest)
        os.utime(dest, ns=(st.st_atime_ns, st.st_mtime_ns), follow_symlinks=False)
        print("%s %d %d" % (h.hexdigest(), st.st_size, int(st.st_mtime)))
        return 0
    finally:
        os.close(sfd)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
