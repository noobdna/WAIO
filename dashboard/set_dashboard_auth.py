#!/usr/bin/env python3
"""dashboard/set_dashboard_auth.py -- writes the HTTP Basic credential
file that dashboard/serve_dashboard.py requires before it will bind a
non-loopback address (see that file's "Access policy" header).

Stores only "user:pbkdf2_sha256$iterations$salt$hash" -- never the
password -- at a path outside the repo, created mode 0600. A missing
directory is created mode 0700; an existing one keeps its own mode. The
password is read interactively (no echo) and never appears on the
command line, in shell history, or in any log.

  python3 dashboard/set_dashboard_auth.py --user ipad \\
      --out ~/.config/waio/dashboard-auth

--password-stdin reads one line from stdin instead of prompting (for
tests and scripted setup).
"""

import argparse
import base64
import getpass
import hashlib
import os
import secrets
import sys
from pathlib import Path

ITERATIONS = 200000
MIN_PASSWORD_LENGTH = 12
REPO_ROOT = Path(__file__).resolve().parent.parent


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--user", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--password-stdin", action="store_true")
    args = ap.parse_args()

    if not args.user or ":" in args.user or not args.user.isprintable():
        sys.exit("error: --user must be non-empty, printable, and contain no ':'")
    out = Path(os.path.expanduser(args.out)).resolve()
    try:
        out.relative_to(REPO_ROOT)
        sys.exit(f"error: refusing to write credentials inside the repository ({REPO_ROOT})")
    except ValueError:
        pass

    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = getpass.getpass("Dashboard password: ")
        if getpass.getpass("Repeat: ") != password:
            sys.exit("error: passwords do not match")
    if len(password) < MIN_PASSWORD_LENGTH:
        sys.exit(f"error: password must be at least {MIN_PASSWORD_LENGTH} characters")

    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    line = "%s:pbkdf2_sha256$%d$%s$%s\n" % (
        args.user, ITERATIONS, base64.b64encode(salt).decode(), base64.b64encode(digest).decode())

    out.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".tmp")
    # O_EXCL|O_NOFOLLOW: never reuse or follow a pre-existing tmp path
    # (a planted symlink would otherwise be chmod'ed and overwritten).
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        sys.exit(f"error: {tmp} already exists (left by an interrupted run?); remove it and retry")
    try:
        with os.fdopen(fd, "w") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(line)
        os.replace(tmp, out)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    print(f"wrote {out} (user={args.user}, pbkdf2_sha256, {ITERATIONS} iterations)")


if __name__ == "__main__":
    main()
