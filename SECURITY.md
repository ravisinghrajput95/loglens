# Security

LogLens reads log files, which are attacker-influenced input in most systems:
user agents, usernames, request paths and error messages that echo user input
all end up in logs. It then optionally puts that content in front of a language
model. Both facts shape what follows.

## Reporting a vulnerability

Open a [security advisory](https://github.com/ravisinghrajput95/loglens/security/advisories/new)
rather than a public issue. Please include the log content that triggers the
problem, with your own secrets removed.

## What the tool defends against, and how well

**Credentials in log text.** JWTs, AWS/GitHub/Slack/Stripe keys,
connection-string passwords, auth headers, `password=` style assignments,
emails, Luhn-valid card numbers and SSNs are replaced with typed placeholders
at parse time, before anything is retained in memory. What was removed is
reported. Disable with `--no-redact` only for logs you know are clean.

This is pattern matching. Secret formats change and new ones appear; a detector
built from patterns will always trail them. Do not rely on it as the only
control over which logs you feed in.

**Prompt injection.** Tool output is fenced and labelled as data, the system
prompt states that log content is never an instruction, and lines matching
known injection phrasings are flagged and surfaced as a security finding rather
than dropped.

Measured effect, from `python -m evals.run --ablate`:

| Model | No defences | Full safety layer |
| --- | --- | --- |
| `llama3.2` (3B) | 4/4 complied with the injection | 0/4 |
| `gemma4` (8B) | 0/2 complied | 0/2 |

The defence matters for the weaker model and is redundant for the stronger one.
Detection is pattern-based, so an attacker who knows the patterns can phrase
around it. Treat it as raising the cost of an attack, not preventing one.

**Answer verification.** Every citation in a generated answer is checked
against what the tools returned. Citations that do not exist are reported as
fabricated, and citations resting on injection-flagged lines are reported as
poisoned evidence. What this cannot do is judge whether a real line supports
the claim made about it; `evals/verifier_bench.py` carries five wrong answers
that pass unflagged, and prints them on every run.

**Regular expressions.** `search_logs` accepts a pattern from the model or the
user. Patterns with nested quantifiers are refused before running, because
Python's `re` has no timeout and a catastrophic backtrack cannot be interrupted
from another thread.

## What it does not defend against

- **Egress.** `--base-url` will send log content to any endpoint you point it
  at. The default is `localhost`. Nothing warns you when you change it.
- **Access control.** There is none. Anyone who can run the binary can read any
  log file the process can read.
- **Audit.** No record is kept of which lines were read or sent to a model.
- **Denial of service.** A hostile log can be arbitrarily large. Memory is
  bounded; time is not.

If you are running this against logs subject to a compliance regime, treat the
redaction as a convenience and not as the control.
