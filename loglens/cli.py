"""Command line interface: one-shot questions and an interactive session."""

import argparse
import sys

from . import __version__, tools
from .agent import DEFAULT_BASE_URL, DEFAULT_MODEL, build_agent
from .verify import format_report, suspicious_ids, verify

USAGE = """LogLens {version} — log triage, with optional AI narration

  loglens report FILE            a full triage report, instantly, no model needed
  loglens report FILE --explain  the same report, then narrated by a local model
  loglens ask "question"         ask the agent a question about a log
  loglens                        interactive session

`report` needs nothing installed but Python. `ask` and `--explain` need Ollama.
Run `loglens report --help` or `loglens ask --help` for the options of each.
"""

BANNER = """LogLens {version} — log analysis agent
model: {model} via {base_url}

Ask about a log file, for example:
  Analyze ./app.log and tell me what broke
  What is the largest error pattern in /var/log/app.log?

Type 'exit' or press Ctrl-D to quit.
"""

EXIT_WORDS = {"exit", "quit", ":q", "bye"}


def build_report_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="loglens report",
        description="Print a deterministic triage report for a log file.",
        epilog="Computed entirely in Python. --explain adds narration from a model.",
    )
    parser.add_argument(
        "file",
        nargs="+",
        help="Log file(s) to read. Several are merged into one timeline, which "
        "is how a trace can be followed across services.",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Also narrate the report using a local model (needs Ollama).",
    )
    parser.add_argument("--since", help="Only entries at or after this time (30m, 2h, ISO).")
    parser.add_argument("--until", help="Only entries at or before this time.")
    parser.add_argument(
        "--bucket", type=int, default=60, help="Anomaly bucket size in seconds."
    )
    parser.add_argument("-m", "--model", default=DEFAULT_MODEL)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument(
        "--infer-severity",
        action="store_true",
        help="For formats with no level field (syslog and similar), classify "
        "entries by message wording. Inferred levels are marked '~'.",
    )
    parser.add_argument("--no-redact", action="store_true")
    parser.add_argument("--no-verify", action="store_true")
    parser.add_argument("--no-stream", action="store_true")
    return parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="loglens",
        description="Investigate log files with a local LLM.",
        epilog="With no question, loglens starts an interactive session. "
        "See `loglens report --help` for the no-model report.",
    )
    parser.add_argument(
        "question",
        nargs="*",
        help="The question to ask. Omit to start an interactive session.",
    )
    parser.add_argument(
        "-m",
        "--model",
        default=DEFAULT_MODEL,
        help=f"Ollama model to use (default: {DEFAULT_MODEL}, env: LOGLENS_MODEL).",
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"Ollama endpoint (default: {DEFAULT_BASE_URL}, env: OLLAMA_BASE_URL).",
    )
    parser.add_argument(
        "--no-redact",
        action="store_true",
        help="Do not strip credentials and personal data from log lines. "
        "Only for logs you know are clean; roughly halves parse time.",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip checking that quoted passages appear in the tool output.",
    )
    parser.add_argument(
        "--no-stream",
        action="store_true",
        help="Wait for the complete answer instead of streaming it.",
    )
    parser.add_argument("--version", action="version", version=f"loglens {__version__}")
    return parser


def _connection_hint(exc: Exception, model: str, base_url: str) -> str | None:
    """Suggest a fix, but only when the failure actually looks like one.

    Printing 'is Ollama running?' after an unrelated internal error sends
    people to check something that was never wrong.
    """
    text = str(exc).lower()
    if any(word in text for word in ("connect", "refused", "timeout", "unreachable")):
        return f"Could not reach Ollama at {base_url}. Start it with 'ollama serve'."
    if any(word in text for word in ("not found", "no such model", "pull")):
        return f"The model may not be installed. Try 'ollama pull {model}'."
    return None


def _report(exc: Exception, model: str, base_url: str) -> None:
    print(f"Agent error: {exc}", file=sys.stderr)
    hint = _connection_hint(exc, model, base_url)
    if hint:
        print(hint, file=sys.stderr)


def _check(answer: str, tool_outputs: list[str]) -> None:
    """Warn when an answer cites lines that do not exist or are hostile."""
    if not answer or not tool_outputs:
        return
    report = verify(answer, tool_outputs, suspicious_ids(tool_outputs))
    warning = format_report(report)
    if warning:
        print("\n" + warning, file=sys.stderr, flush=True)


def ask(agent, history: list, question: str, stream: bool, check: bool = True) -> list:
    """Send one question, print the answer, and return the updated history.

    History is threaded back in so follow-up questions like 'what about the
    payment service?' resolve against what was already established. Only the
    question and the answer are kept: replaying tool traffic would grow the
    context quickly without helping the model answer the next question.

    Tool output is collected as it goes so the finished answer can be checked
    against it — see loglens.verify.
    """
    messages = history + [("user", question)]
    tool_outputs: list[str] = []

    if not stream:
        result = agent.invoke({"messages": messages})
        for message in result["messages"]:
            if getattr(message, "type", None) == "tool":
                tool_outputs.append(str(message.content))
        answer = result["messages"][-1].content
        print(answer)
        if check:
            _check(answer, tool_outputs)
        return messages + [("assistant", answer)]

    # Tool calls are announced on stderr as they happen, so a multi-step
    # investigation doesn't look like a hang, and stdout stays clean enough
    # to pipe. The answer itself streams token by token.
    parts: list[str] = []
    for chunk, metadata in agent.stream({"messages": messages}, stream_mode="messages"):
        for call in getattr(chunk, "tool_calls", None) or []:
            if call.get("name"):
                print(f"  · {call['name']}", file=sys.stderr, flush=True)

        content = getattr(chunk, "content", "")
        if not content:
            continue

        node = metadata.get("langgraph_node")
        if node == "model":
            print(content, end="", flush=True)
            parts.append(content)
        elif node == "tools":
            tool_outputs.append(str(content))

    if parts:
        print()

    answer = "".join(parts)
    if check:
        _check(answer, tool_outputs)

    return messages + [("assistant", answer)]


def interactive(agent, model: str, base_url: str, stream: bool, check: bool = True) -> int:
    print(BANNER.format(version=__version__, model=model, base_url=base_url))
    history: list = []

    while True:
        try:
            question = input("loglens> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if not question:
            continue
        if question.lower() in EXIT_WORDS:
            return 0

        try:
            history = ask(agent, history, question, stream, check)
        except KeyboardInterrupt:
            print("\n(interrupted)", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001 — reported, not swallowed
            _report(exc, model, base_url)


def report_command(argv: list[str]) -> int:
    """Print a deterministic report, optionally narrated."""
    from .analysis import in_window
    from .parser import load_many, parse_time_spec, restrict
    from .report import render

    args = build_report_parser().parse_args(argv)

    try:
        since = parse_time_spec(args.since)
        until = parse_time_spec(args.until)
    except ValueError as exc:
        print(f"Invalid time range: {exc}", file=sys.stderr)
        return 2

    label = args.file[0] if len(args.file) == 1 else f"{len(args.file)} files"
    try:
        result = load_many(
            args.file,
            redact_secrets=not args.no_redact,
            infer_severity=args.infer_severity,
        )
    except FileNotFoundError as exc:
        print(f"No log file at '{exc.filename or args.file[0]}'.", file=sys.stderr)
        return 1
    except IsADirectoryError as exc:
        print(
            f"'{exc.filename or args.file[0]}' is a directory, not a log file.",
            file=sys.stderr,
        )
        return 1
    except OSError as exc:
        print(f"Could not read log: {exc}", file=sys.stderr)
        return 1

    if not result.entries:
        print(
            f"No log entries recognised in '{args.file}' ({result.total_lines} line(s) read).",
            file=sys.stderr,
        )
        return 1

    if since or until:
        windowed = in_window(result.entries, since, until)
        if not windowed:
            print("No entries in that time range.", file=sys.stderr)
            return 1
        if result.truncated:
            print(
                "Note: the file was larger than the retained window, so a time "
                "filter can only see the most recent entries.",
                file=sys.stderr,
            )
        result = restrict(result, windowed)

    text = render(result, label, bucket_seconds=args.bucket)
    print(text)

    if not args.explain:
        return 0

    from .explain import explain

    print("\nEXPLANATION")
    print("─" * 78)
    try:
        explain(
            text,
            model=args.model,
            base_url=args.base_url,
            stream=not args.no_stream,
            check=not args.no_verify,
        )
    except Exception as exc:  # noqa: BLE001 — reported, not raised
        _report(exc, args.model, args.base_url)
        # The report itself already printed and is still valid.
        return 1

    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # Subcommands are dispatched before argparse so that `loglens "a question"`
    # keeps working — the question is a positional, not a subcommand.
    if argv and argv[0] == "report":
        return report_command(argv[1:])
    if argv and argv[0] == "ask":
        argv = argv[1:]
    if argv and argv[0] in ("help", "--usage"):
        print(USAGE.format(version=__version__))
        return 0

    args = build_parser().parse_args(argv)
    stream = not args.no_stream
    check = not args.no_verify
    tools.REDACT_SECRETS = not args.no_redact

    try:
        agent = build_agent(model=args.model, base_url=args.base_url)
    except Exception as exc:  # noqa: BLE001
        print(f"Could not start the agent: {exc}", file=sys.stderr)
        hint = _connection_hint(exc, args.model, args.base_url)
        if hint:
            print(hint, file=sys.stderr)
        return 1

    if args.question:
        try:
            ask(agent, [], " ".join(args.question), stream, check)
        except KeyboardInterrupt:
            return 130
        except Exception as exc:  # noqa: BLE001
            _report(exc, args.model, args.base_url)
            return 1
        return 0

    if not sys.stdin.isatty():
        question = sys.stdin.read().strip()
        if not question:
            print("No question given.", file=sys.stderr)
            return 1
        ask(agent, [], question, stream, check)
        return 0

    return interactive(agent, args.model, args.base_url, stream, check)


if __name__ == "__main__":
    raise SystemExit(main())
