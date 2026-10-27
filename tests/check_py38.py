#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Joël Maizi
"""Syntax that Python 3.8 refuses but a recent Python accepts, in the files given.

The tests run on a recent Python on the development machine and would not notice it. Checked:
an f-string that reuses its own quote inside a replacement field (f"{d["k"]}", Python 3.12+), and
a backslash or a comment inside a replacement field."""
import ast
import io
import sys
import tokenize

FSTART = getattr(tokenize, "FSTRING_START", None)
FMIDDLE = getattr(tokenize, "FSTRING_MIDDLE", None)
FEND = getattr(tokenize, "FSTRING_END", None)


def quote_of(text):
    body = text.lstrip("rRbBfFuU")
    return body[:3] if body[:3] in ('"""', "'''") else body[:1]


def check(path):
    problems = []
    with open(path, "rb") as f:
        src = f.read()
    try:
        ast.parse(src, feature_version=(3, 8))
    except SyntaxError as e:
        return [f"{path}:{e.lineno}: {e.msg}"]
    if FSTART is None:  # Python < 3.12 tokenizes f-strings as plain strings: it refuses them itself
        return problems
    stack = []  # (quote, line) of the f-strings being read
    for tok in tokenize.tokenize(io.BytesIO(src).readline):
        if tok.type == FSTART:
            if stack and quote_of(tok.string) == stack[-1][0]:
                problems.append(f"{path}:{tok.start[0]}: f-string inside an f-string with the same quote "
                                f"(Python 3.12+ only)")
            stack.append((quote_of(tok.string), tok.start[0]))
        elif tok.type == FEND:
            stack.pop()
        elif stack and tok.type == tokenize.STRING and quote_of(tok.string) == stack[-1][0]:
            problems.append(f"{path}:{tok.start[0]}: string with the quote of the f-string around it "
                            f"(Python 3.12+ only)")
        elif stack and tok.type == tokenize.COMMENT:
            problems.append(f"{path}:{tok.start[0]}: comment inside an f-string replacement field")
    return problems


if __name__ == "__main__":
    bad = [p for path in sys.argv[1:] for p in check(path)]
    print("\n".join(bad))
    sys.exit(1 if bad else 0)
