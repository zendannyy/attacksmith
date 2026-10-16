#!/usr/bin/env python3

import re
import sys
import uuid

ID_LINE = re.compile(
    r"^id:\s*['\"]?([^'\"\s#]+)['\"]?",
    re.MULTILINE,
)


def is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


def stamp_id(path: str) -> bool:
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()

    match = ID_LINE.search(text)
    if match and is_uuid(match.group(1)):
        return False

    new_id = str(uuid.uuid4())
    if match:
        start, end = match.span(1)
        text = text[:start] + new_id + text[end:]
    else:
        title = re.search(r"^title:.*$", text, re.MULTILINE)
        insert_at = title.end() if title else 0
        prefix = "" if insert_at == 0 or text[:insert_at].endswith("\n") else "\n"
        text = text[:insert_at] + f"{prefix}id: {new_id}\n" + text[insert_at:]

    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    print(f"{path}: wrote id {new_id}", file=sys.stderr)
    return True


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Usage: python3 gen_uuid.py <file.yml> [...]")
    changed = False
    for path in sys.argv[1:]:
        if stamp_id(path):
            changed = True
    sys.exit(1 if changed else 0)
