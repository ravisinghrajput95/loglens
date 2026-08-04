# LogLens

An AI log analysis agent for incident investigation. It runs against a local LLM through [Ollama](https://ollama.com), so your logs never leave your machine.

The point of LogLens is that the analysis lives in real tools, not in the model. The LLM decides *what to look at*; deterministic Python decides *what is true*. That division is what keeps it from inventing findings.

Real output, abridged:

```
$ loglens "Analyze ./app.log. What broke and why?"
  · summarize_logs
  · top_errors
  · trace_timeline

**Summary**
The system experienced significant instability, characterized by a 20.0%
error rate across multiple services. The most critical and traceable issue
is a failure in event publishing from the order-service to Kafka, which
appears to trigger cascading failures in downstream services like
notification-service.

**Findings**
*  Primary Failure (Order Service): failed due to a Kafka connectivity
   timeout. Evidence: error pattern `Failed to publish event to Kafka topic
   orders-v1` with `TimeoutException: Topic orders-v1 not acknowledged
   after 5000ms`.
*  Cascading Failure (Notification Service): SMTP connection failure.
   Evidence: during trace reconstruction for trace_id f82b719c, the
   timeline shows a subsequent error hop ...
```

---

## What it can actually do

| Tool | What it answers |
| --- | --- |
| `summarize_logs` | How healthy is this? Counts per level, per-service breakdown, time span, error rate |
| `search_logs` | Show me the real lines — filter by level, service, regex, or trace id |
| `top_errors` | What keeps failing? Similar errors grouped into patterns with counts |
| `trace_timeline` | Reconstruct one request across services, with the gap between each hop |
| `detect_anomalies` | When did failures cluster, and what was unusually slow? |

Two of these do most of the work.

**Error grouping.** Messages that differ only in an id, hostname, or duration collapse into a single pattern. `Connection timeout after 5000ms to postgres-01` and `Connection timeout after 3000ms to postgres-04` become one entry reading `[2x] Connection timeout after <N>ms to <NAME>`. A fault hitting forty hosts shows up as one pattern with a count of forty, instead of forty lines that look unrelated.

**Trace reconstruction.** If your logs carry a `trace_id`, `trace_timeline` orders one request across every service it touched and shows the elapsed time between hops:

```
   start     20:17:00 ERROR order-service    Failed to publish to Kafka orders-v1  <-- FAILURE
+    5847ms  20:17:05 WARN  order-service    Circuit breaker switched to OPEN
+    2564ms  20:17:08 ERROR notification-svc SMTP server connection refused        <-- FAILURE
+    7213ms  20:17:15 INFO  notification-svc Retry scheduled after 30 seconds
```

This is what separates a cause from its symptoms. The SMTP failure looks like an independent problem until you see it sitting downstream of the Kafka timeout on the same trace.

---

## Install

Requires Python 3.11+ and a running Ollama.

```bash
git clone https://github.com/ravisinghrajput95/loglens.git
cd loglens

python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .

ollama pull gemma4
ollama serve
```

## Use

```bash
# One question
loglens "Analyze ./app.log and tell me the root cause"

# Interactive session — follow-up questions keep their context
loglens

# A faster, weaker model, or a remote Ollama
loglens -m llama3.2 "What is the biggest error pattern in /var/log/app.log?"
loglens --base-url http://gpu-box:11434 "Summarize ./app.log"
```

| Setting | Flag | Environment variable | Default |
| --- | --- | --- | --- |
| Model | `-m`, `--model` | `LOGLENS_MODEL` | `gemma4` |
| Ollama endpoint | `--base-url` | `OLLAMA_BASE_URL` | `http://localhost:11434` |
| Streaming | `--no-stream` to disable | — | on |

Tool calls print to stderr and the answer to stdout, so `loglens "..." > report.md` captures the report without the progress noise.

### Docker

The image does not bundle Ollama; point it at one you are already running.

```bash
docker build -t loglens .
docker run --rm -it \
  -e OLLAMA_BASE_URL=http://host.docker.internal:11434 \
  -v "$PWD/app.log:/logs/app.log:ro" \
  loglens "Analyze /logs/app.log"
```

---

## Log formats

Detected per line, so a file containing several formats is fine:

| Format | Example |
| --- | --- |
| JSON lines | `{"timestamp":"...","level":"ERROR","service":"api","message":"..."}` |
| logback / log4j / python | `2026-07-30 20:15:31,123 ERROR [order-service] com.foo.Bar - message` |
| nginx error | `2026/07/30 20:15:31 [error] 1234#0: *1 upstream timed out` |
| syslog | `Jul 30 20:15:31 web-01 nginx[1234]: message` |
| bracketed | `[2026-07-30T20:15:31Z] [ERROR] [api] message` |

JSON keys are matched flexibly — `message`/`msg`, `trace_id`/`traceId`, `latency_ms`/`duration_ms` — and any key it doesn't model is kept and searchable.

Multi-line stack traces fold into the entry they belong to, including the unindented header line that names the real exception. Gzipped logs (`.log.gz`) are read directly.

**Scale.** Files are streamed and retained entries are capped, so peak memory tracks entries kept rather than file size: a 48 MB file loads at roughly 67 MB, and a 5 GB file loads at the same. When a file exceeds the cap, the tools say so rather than silently analysing a fraction of it.

---

## How it avoids making things up

The system prompt forbids inventing log entries, but a prompt alone doesn't achieve that. The design does:

- Every claim traces to tool output computed in Python, not to the model reading raw text.
- Tools report their own limits. Too few time buckets to judge a spike, too few `latency_ms` samples for a baseline, a file truncated by the cap — each is stated rather than papered over.
- Failures come back as text the model can relay. A missing file or a bad regex returns a message instead of raising, so a mistake produces a useful reply rather than a crash.
- The parser refuses to guess. A prose sentence containing the word "error" is not counted as an ERROR entry.

**The model is still the weak link, and model choice matters more than you would expect.** The tools are deterministic; the narration around them is not.

Measured on the sample log, asking for the most serious problem and its cause:

| Model | Time | Tools used | Followed the trace | Figures correct |
| --- | --- | --- | --- | --- |
| `gemma4` (8B) | ~200s | 4 of 5 | yes | 3 of 3 |
| `qwen3` (8B) | ~130s | 2 of 5 | no | 2 of 3 |
| `llama3.2` (3B) | ~25s | 1–3 of 5 | sometimes | 2 of 3 |

`gemma4` is the default despite being the slowest, because of what the faster models do when they stop early.

Asked a short question — *"Analyze ./app.log. What broke and why?"* — `llama3.2` called only `summarize_logs`, which returns counts and no log lines, and then **invented eight log entries** and quoted them as evidence, in a text format this JSON file does not use. Strengthening the system prompt did not fix it. Given a longer, more explicit question it used three tools and behaved well, so its failure depends on how you phrase the request, which is not a property you want to rely on during an incident.

A tool that fabricates evidence is worse than no tool, so the default is the model that was not observed doing it. If you want speed and will read the output critically, `-m llama3.2` answers in seconds — just ask detailed questions, and treat quoted log lines as unverified.

This is the honest limit of the current design: the tools cannot be made to lie, but nothing yet checks that the model's final answer only quotes what the tools returned.

---

## Development

```bash
pip install -e ".[dev]"
pytest              # 151 tests
ruff check . && ruff format --check .
```

CI runs lint, format check, and tests on Python 3.11, 3.12 and 3.13.

```text
loglens/
├── models.py     LogEntry, level normalization
├── parser.py     format detection, streaming reads, stack traces
├── analysis.py   pure functions — the actual analysis
├── tools.py      LangChain tools wrapping those functions
├── agent.py      model wiring and system prompt
└── cli.py        argument parsing, interactive session, streaming
```

`analysis.py` has no LangChain dependency and holds no state, which is why the test suite can cover it directly.

## Not built yet

Live tailing, multi-file correlation, Kubernetes and Loki sources, and a structured report export.

## License

MIT
