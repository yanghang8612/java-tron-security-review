"""Idempotently insert one include after the unique HTTP 6060 listener.

Deliberately refuses ambiguous layouts; the shell installer validates and rolls back.
"""
from pathlib import Path
import os
import re
import sys
import tempfile

INCLUDE = "include /etc/nginx/snippets/jtsr-report-web.conf;"


def configure(content: str) -> str:
    if INCLUDE in content:
        return content
    if re.search(r"^\s*location\b[^\n]*?/security", content, re.MULTILINE):
        raise ValueError("an existing /security route must be reviewed manually")
    listener = re.compile(r"^([ \t]*)listen[ \t]+6060[ \t]*;[ \t]*$", re.MULTILINE)
    if len(listener.findall(content)) != 1:
        raise ValueError("expected exactly one standalone listen 6060 directive")
    return listener.sub(lambda match: match[0] + "\n" + match[1] + INCLUDE, content, count=1)


if __name__ == "__main__":
    path = Path(sys.argv[1])
    if path.is_symlink() or not path.is_file():
        raise SystemExit("Nginx config must be a regular non-symlink file")
    before = path.read_text()
    after = configure(before)
    if after != before:
        info = path.stat()
        fd, temporary = tempfile.mkstemp(prefix=".jtsr-", dir=path.parent)
        try:
            with os.fdopen(fd, "w") as stream:
                stream.write(after)
                os.fchmod(stream.fileno(), info.st_mode & 0o777)
                os.fchown(stream.fileno(), info.st_uid, info.st_gid)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
