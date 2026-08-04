"""Entry point. Ask the agent a question about a log file."""

from loglens.agent import build_agent


def main() -> None:
    agent = build_agent()

    question = input("Enter your question for the DevOps agent: ").strip()
    if not question:
        print("No question given.")
        return

    print("\nThinking...\n")
    result = agent.invoke({"messages": [("user", question)]})
    print(result["messages"][-1].content)


if __name__ == "__main__":
    main()
