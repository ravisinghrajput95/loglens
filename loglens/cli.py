"""Command line entry point."""

import sys

from .agent import DEFAULT_BASE_URL, DEFAULT_MODEL, build_agent


def main() -> int:
    """Ask the agent one question about a log file."""
    agent = build_agent()

    question = " ".join(sys.argv[1:]).strip()
    if not question:
        try:
            question = input("Enter your question for the DevOps agent: ").strip()
        except (EOFError, KeyboardInterrupt):
            return 1

    if not question:
        print("No question given.", file=sys.stderr)
        return 1

    print("\nThinking...\n")
    try:
        result = agent.invoke({"messages": [("user", question)]})
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001 - surfaced to the user, not swallowed
        print(f"Agent failed: {exc}", file=sys.stderr)
        print(
            f"Check that Ollama is running at {DEFAULT_BASE_URL} and that the "
            f"'{DEFAULT_MODEL}' model is available (`ollama pull {DEFAULT_MODEL}`).",
            file=sys.stderr,
        )
        return 1

    print(result["messages"][-1].content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
