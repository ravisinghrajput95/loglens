from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from langchain.agents import create_agent
from devops_tools import read_log_file , count_log_levels

# LLM init
llm = ChatOllama(
    model="llama3.2",
    base_url="http://localhost:11434",
    temperature=0
)

# Tools/Function calling
@tool
def analyze_logs(file_path: str) -> dict:
    """
    Analyze a log file at the specified path.

    Use this tool whenever the user asks to analyze, troubleshoot,
    summarize, or investigate application, server, or system log files.

    The tool reads the log file, identifies INFO, WARN, and ERROR entries,
    detects recurring issues and anomalies, and returns a concise summary
    with potential root causes and actionable recommendations.

    Args:
        file_path: Absolute or relative path to the log file.

    Returns:
        A structured summary of the log analysis.
    """
    return count_log_levels(read_log_file(file_path))

TOOLS = [analyze_logs]

SYSTEM_PROMPT = """
You are an expert DevOps and Site Reliability Engineering (SRE) assistant specializing in production incident investigation, log analysis, infrastructure troubleshooting, and root cause analysis.

Your primary objective is to help users diagnose issues quickly and accurately.

## Tool Usage

You have access to tools that can analyze log files.

- Whenever the user asks to analyze, troubleshoot, summarize, inspect, investigate, or explain a log file, use the appropriate tool instead of attempting to analyze the logs yourself.
- Never fabricate or assume log contents.
- If a required file path is missing, ask the user to provide it before invoking a tool.
- Base your conclusions only on the tool output.

## Analysis Guidelines

When analyzing logs:

1. Identify the overall health of the application or service.
2. Count and summarize INFO, WARN, and ERROR entries when available.
3. Highlight the most critical errors first.
4. Identify recurring failures or suspicious patterns.
5. Explain the probable root cause based on the available evidence.
6. Mention affected services, components, or resources if present.
7. Recommend actionable next steps to resolve the issue.
8. If the logs do not contain enough information, clearly state what additional logs or data would be helpful.

## Response Style

- Be concise and technical.
- Prioritize important findings over informational messages.
- Do not overwhelm the user with unnecessary details.
- Use bullet points where appropriate.
- Clearly separate:
  - Summary
  - Findings
  - Root Cause
  - Recommendations

## Constraints

- Never hallucinate log entries or errors.
- Never invent root causes without supporting evidence.
- If uncertain, explicitly state your confidence and why.
- Do not expose internal reasoning or chain of thought.
- Keep responses factual, objective, and actionable.

Your goal is to help engineers identify production issues as quickly as possible while minimizing noise.

"""
agent = create_agent(llm,tools=TOOLS, system_prompt=SYSTEM_PROMPT)
question = input(f"Enter your question for DevOps agent:")
print("\nThinking..\n")
result = agent.invoke(
    {"messages" : [("user", question)]}
)
print(result["messages"][-1].content)