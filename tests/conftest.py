"""Shared fixtures. Log content lives here rather than in files so each test
reads as a statement about specific input."""

import gzip
import textwrap

import pytest

JSON_LOG = textwrap.dedent("""\
    {"timestamp":"2026-07-30T20:15:31Z","level":"INFO","service":"api-gateway","host":"api-01","message":"Incoming request","trace_id":"t-1"}
    {"timestamp":"2026-07-30T20:15:32Z","level":"WARN","service":"api-gateway","host":"api-01","message":"Rate limit at 85%","trace_id":"t-1"}
    {"timestamp":"2026-07-30T20:16:00Z","level":"ERROR","service":"order-service","host":"order-02","message":"Failed to publish to Kafka topic orders-v1","trace_id":"t-1","exception":"TimeoutException: not acknowledged after 5000ms"}
    {"timestamp":"2026-07-30T20:16:05Z","level":"ERROR","service":"payment-service","host":"pay-01","message":"Payment gateway returned HTTP 503","trace_id":"t-2","latency_ms":900}
    {"timestamp":"2026-07-30T20:16:09Z","level":"INFO","service":"api-gateway","host":"api-01","message":"Completed request","trace_id":"t-1","latency_ms":38000}
    """)


@pytest.fixture
def json_log(tmp_path):
    path = tmp_path / "app.log"
    path.write_text(JSON_LOG)
    return str(path)


@pytest.fixture
def gzipped_log(tmp_path):
    path = tmp_path / "app.log.gz"
    with gzip.open(path, "wt") as handle:
        handle.write(JSON_LOG)
    return str(path)


@pytest.fixture
def java_log(tmp_path):
    """A logback file whose ERROR carries a multi-line stack trace."""
    path = tmp_path / "java.log"
    path.write_text(
        "2026-07-30 20:15:31,001 INFO  [api] Request received\n"
        "2026-07-30 20:15:32,004 ERROR [order-service] Failed to publish\n"
        "java.net.SocketTimeoutException: Read timed out\n"
        "\tat java.base/java.net.SocketInputStream.read(SocketInputStream.java:168)\n"
        "\tat org.apache.kafka.Producer.send(Producer.java:940)\n"
        "Caused by: java.io.IOException: Broken pipe\n"
        "\t... 14 more\n"
        "2026-07-30 20:15:33,010 INFO  [api] Request completed\n"
    )
    return str(path)


@pytest.fixture
def mixed_log(tmp_path):
    """One file containing three different formats, which is the normal case
    when logs from several systems are concatenated."""
    path = tmp_path / "mixed.log"
    path.write_text(
        '{"timestamp":"2026-07-30T20:15:31Z","level":"INFO","service":"api","message":"start"}\n'
        "2026-07-30 20:15:32,000 ERROR [db] Connection timeout after 5000ms to postgres-01\n"
        "2026-07-30 20:15:33,000 ERROR [db] Connection timeout after 9000ms to postgres-07\n"
        "Jul 30 20:15:34 web-01 nginx[99]: upstream timed out\n"
    )
    return str(path)


@pytest.fixture(autouse=True)
def clear_tool_cache():
    """Tools cache parsed files by path+mtime; tmp_path can repeat across tests."""
    from loglens.tools import _CACHE

    _CACHE.clear()
    yield
    _CACHE.clear()
