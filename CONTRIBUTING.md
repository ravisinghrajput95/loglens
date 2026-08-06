# Contributing

```bash
pip install -e ".[dev]"
pytest                    # 398 tests
python -m evals.run       # tool correctness, format coverage, verifier scores
ruff check . && ruff format --check .
```

All four run in CI on Python 3.11, 3.12 and 3.13.

## Adding a log format

`loglens/parser.py` holds the patterns, tried in order. Adding one means:

1. A pattern in `_TEXT_PATTERNS`, or a dedicated function if the format is
   structured enough to deserve one (see `parse_logfmt_line`).
2. A case in `tests/test_realworld_formats.py` with a line in the real shape.
3. A sample in `evals/formats.py`, so a regression fails the build.
4. A line in the `TestNoFalsePositivesFromTheNewPatterns` list if the format
   is loose enough to risk matching prose.

Point four is not optional. Every pattern is a new way to mistake an English
sentence for a log line, and the parser silently counting prose as ERROR
entries is a bug that reached the README once already.

## Changing anything that checks something

If you add or change a check — verification, injection detection, an eval —
add a test that proves it can **fail**. This project has three recorded cases
of a check that reported success because it was not in a position to find
anything: a verifier that confirmed provenance rather than truth, a monitor
filter that matched only the success path, and an ablation that never exposed
the model to the attack it was measuring.

Silence is not evidence. A check whose failure mode is silence needs a separate
signal proving it could have fired.

## Claims in the README

Numbers in the README come from `evals/`. If you change behaviour that moves
one, re-run the harness and update the number in the same commit. A stale
benchmark is worse than none, because it reads as measurement.
