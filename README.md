# AI Log Analysis Agent

An AI-powered log analysis assistant built with **LangChain** and **Ollama** that helps engineers analyze application and server logs using a local Large Language Model (LLM).

The agent can inspect log files, identify errors and warnings, summarize findings, and provide concise troubleshooting recommendations—all while running locally.

---

## Features

* 🤖 AI-powered log analysis using a local LLM
* 🦙 Powered by Ollama
* 📊 Counts `INFO`, `WARN`, and `ERROR` log entries
* 🔍 Identifies recurring issues and anomalies
* 📄 Generates concise log summaries
* ⚡ Suggests probable root causes
* 🛠️ Tool-based architecture using LangChain

---

## Project Structure

```text
.
├── __pycache__/
├── agent.py             # LangChain agent and application entry point
├── app.log              # Sample log file
├── devops_tools.py      # Custom tools used by the agent
└── requirements.txt     # Project dependencies
```

---

## Prerequisites

* Python 3.11+
* Ollama installed
* A downloaded Ollama model (e.g. `llama3.2`, `llama3.1`, `qwen3`, `mistral`)

---

## Installation

### Clone the repository

```bash
git clone https://github.com/<your-username>/ai-log-analysis-agent.git

cd ai-log-analysis-agent
```

### Create a virtual environment

```bash
python -m venv .venv
```

Activate it:

**macOS / Linux**

```bash
source .venv/bin/activate
```

**Windows**

```powershell
.venv\Scripts\activate
```

### Install dependencies

```bash
pip install -r requirements.txt
```

---

## Install and Start Ollama

Download the model you want to use.

Example:

```bash
ollama pull llama3.2
```

Start the Ollama server:

```bash
ollama serve
```

---

## Usage

Run the agent:

```bash
python agent.py
```

Example prompt:

```text
Analyze the log file located at ./app.log
```

Example response:

```text
Summary
-------
INFO : 15
WARN : 4
ERROR : 2

Key Findings
------------
• Multiple database connection timeouts detected.
• Kafka publish failures observed.
• High memory utilization warnings.

Probable Root Cause
-------------------
The application is experiencing intermittent database connectivity issues.

Recommendations
---------------
• Verify database availability.
• Review database connection pool configuration.
• Check network connectivity.
```

---

## Sample Log Format

```json
{"timestamp":"2026-07-30T20:15:31Z","level":"INFO","service":"api-gateway","message":"Incoming request"}
{"timestamp":"2026-07-30T20:15:32Z","level":"WARN","service":"api-gateway","message":"Rate limit exceeded"}
{"timestamp":"2026-07-30T20:15:33Z","level":"ERROR","service":"order-service","message":"Kafka publish failed"}
```

---

## Future Enhancements

* Kubernetes log analysis
* NGINX log parsing
* Docker log support
* Multi-file log analysis
* Streaming log monitoring
* Root cause correlation
* Grafana Loki integration

---

## License

This project is licensed under the MIT License.
