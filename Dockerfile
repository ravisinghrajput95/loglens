# The agent talks to an Ollama server over HTTP; it does not bundle one.
# Point it at a host Ollama with:
#   docker run --rm -it \
#     -e OLLAMA_BASE_URL=http://host.docker.internal:11434 \
#     -v "$PWD/app.log:/logs/app.log:ro" \
#     loglens "Analyze /logs/app.log"

FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    OLLAMA_BASE_URL=http://host.docker.internal:11434

WORKDIR /app

# Dependency metadata first, so edits to source don't invalidate the install layer.
COPY pyproject.toml README.md ./
COPY loglens ./loglens
RUN pip install --no-cache-dir .

# Run as a non-root user; the container only ever needs to read mounted logs.
RUN useradd --create-home --uid 10001 loglens
USER loglens

ENTRYPOINT ["loglens"]
