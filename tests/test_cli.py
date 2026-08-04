"""CLI behaviour. The agent is stubbed out so these run without a live model."""

import pytest

from loglens import cli


class Message:
    """The real agent returns message objects, not tuples."""

    def __init__(self, content):
        self.content = content


class FakeAgent:
    """Stands in for the compiled agent, recording what it was asked."""

    def __init__(self, answer="the answer"):
        self.answer = answer
        self.seen: list = []

    def invoke(self, payload):
        self.seen.append(payload["messages"])
        return {"messages": [Message(self.answer)]}

    def stream(self, payload, stream_mode=None):
        self.seen.append(payload["messages"])
        return iter(())


class Chunk:
    def __init__(self, content="", tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls or []


class TestArgumentParsing:
    def test_help_exits_cleanly(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cli.build_parser().parse_args(["--help"])
        assert exc.value.code == 0
        assert "Investigate log files" in capsys.readouterr().out

    def test_version_exits_cleanly(self):
        with pytest.raises(SystemExit) as exc:
            cli.build_parser().parse_args(["--version"])
        assert exc.value.code == 0

    def test_unknown_flag_is_an_error(self):
        with pytest.raises(SystemExit) as exc:
            cli.build_parser().parse_args(["--nope"])
        assert exc.value.code != 0

    def test_question_words_are_joined(self):
        args = cli.build_parser().parse_args(["analyze", "./app.log"])
        assert args.question == ["analyze", "./app.log"]

    def test_model_and_url_flags(self):
        args = cli.build_parser().parse_args(["-m", "qwen3", "--base-url", "http://x:1"])
        assert args.model == "qwen3"
        assert args.base_url == "http://x:1"

    def test_a_question_is_not_required(self):
        assert cli.build_parser().parse_args([]).question == []


class TestAsk:
    def test_non_streaming_prints_and_records_history(self, capsys):
        agent = FakeAgent("root cause: kafka")
        history = cli.ask(agent, [], "what broke?", stream=False)
        assert "root cause: kafka" in capsys.readouterr().out
        assert history[0] == ("user", "what broke?")
        assert history[-1] == ("assistant", "root cause: kafka")

    def test_history_is_threaded_into_the_next_question(self):
        agent = FakeAgent()
        history = cli.ask(agent, [], "first", stream=False)
        cli.ask(agent, history, "and the second?", stream=False)
        sent = agent.seen[-1]
        assert sent[0] == ("user", "first")
        assert sent[-1] == ("user", "and the second?")

    def test_streaming_prints_tokens_and_keeps_the_answer(self, capsys, monkeypatch):
        agent = FakeAgent()
        chunks = [
            (Chunk(tool_calls=[{"name": "summarize_logs"}]), {"langgraph_node": "tools"}),
            (Chunk("Root "), {"langgraph_node": "model"}),
            (Chunk("cause."), {"langgraph_node": "model"}),
        ]
        monkeypatch.setattr(agent, "stream", lambda p, stream_mode=None: iter(chunks))

        history = cli.ask(agent, [], "why?", stream=True)
        captured = capsys.readouterr()
        assert "Root cause." in captured.out
        # Tool activity goes to stderr so stdout stays pipeable.
        assert "summarize_logs" in captured.err
        assert history[-1] == ("assistant", "Root cause.")

    def test_tool_output_is_not_printed_as_the_answer(self, capsys, monkeypatch):
        agent = FakeAgent()
        chunks = [
            (Chunk("raw tool text"), {"langgraph_node": "tools"}),
            (Chunk("real answer"), {"langgraph_node": "model"}),
        ]
        monkeypatch.setattr(agent, "stream", lambda p, stream_mode=None: iter(chunks))
        cli.ask(agent, [], "q", stream=True)
        out = capsys.readouterr().out
        assert "real answer" in out
        assert "raw tool text" not in out


class TestMain:
    def test_one_shot_question(self, capsys, monkeypatch):
        agent = FakeAgent("done")
        monkeypatch.setattr(cli, "build_agent", lambda **kw: agent)
        assert cli.main(["analyze", "./app.log"]) == 0
        assert agent.seen[0][-1] == ("user", "analyze ./app.log")

    def test_agent_construction_failure_is_reported(self, capsys, monkeypatch):
        def boom(**kwargs):
            raise ConnectionError("connection refused")

        monkeypatch.setattr(cli, "build_agent", boom)
        assert cli.main(["q"]) == 1
        assert "Could not reach Ollama" in capsys.readouterr().err

    def test_agent_failure_during_a_question_is_reported(self, capsys, monkeypatch):
        agent = FakeAgent()
        monkeypatch.setattr(
            agent,
            "stream",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("model not found")),
        )
        monkeypatch.setattr(cli, "build_agent", lambda **kw: agent)
        assert cli.main(["q"]) == 1
        assert "model not found" in capsys.readouterr().err

    def test_flags_reach_the_agent(self, monkeypatch):
        captured = {}

        def spy(**kwargs):
            captured.update(kwargs)
            return FakeAgent()

        monkeypatch.setattr(cli, "build_agent", spy)
        cli.main(["-m", "qwen3", "--base-url", "http://elsewhere:11434", "q"])
        assert captured == {"model": "qwen3", "base_url": "http://elsewhere:11434"}


class TestVerificationWiring:
    """The check must run on real answers, using what the tools returned."""

    def _chunks(self, tool_text, answer):
        return [
            (Chunk(tool_text), {"langgraph_node": "tools"}),
            (Chunk(answer), {"langgraph_node": "model"}),
        ]

    def test_fabricated_quote_warns_on_stderr(self, capsys, monkeypatch):
        agent = FakeAgent()
        chunks = self._chunks(
            "Entries parsed: 25\nError rate: 20.0%",
            "Evidence: `2026-07-30 20:15:31 INFO [k8s] [main] Starting controller`",
        )
        monkeypatch.setattr(agent, "stream", lambda p, stream_mode=None: iter(chunks))

        cli.ask(agent, [], "why?", stream=True, check=True)
        captured = capsys.readouterr()
        assert "do not appear in the tool output" in captured.err
        # The answer itself is still shown; the warning is advisory.
        assert "Starting controller" in captured.out

    def test_grounded_quote_produces_no_warning(self, capsys, monkeypatch):
        agent = FakeAgent()
        chunks = self._chunks(
            "example: Failed to publish event to Kafka topic orders-v1",
            "Evidence: `Failed to publish event to Kafka topic orders-v1`",
        )
        monkeypatch.setattr(agent, "stream", lambda p, stream_mode=None: iter(chunks))

        cli.ask(agent, [], "why?", stream=True, check=True)
        assert "do not appear" not in capsys.readouterr().err

    def test_no_verify_disables_the_check(self, capsys, monkeypatch):
        agent = FakeAgent()
        chunks = self._chunks("counts only", "Evidence: `an entirely invented log line`")
        monkeypatch.setattr(agent, "stream", lambda p, stream_mode=None: iter(chunks))

        cli.ask(agent, [], "why?", stream=True, check=False)
        assert "do not appear" not in capsys.readouterr().err

    def test_non_streaming_path_is_checked_too(self, capsys, monkeypatch):
        class ToolMessage:
            type = "tool"
            content = "Entries parsed: 25"

        agent = FakeAgent()
        monkeypatch.setattr(
            agent,
            "invoke",
            lambda p: {
                "messages": [
                    ToolMessage(),
                    Message("Evidence: `a completely fabricated log line here`"),
                ]
            },
        )
        cli.ask(agent, [], "why?", stream=False, check=True)
        assert "do not appear in the tool output" in capsys.readouterr().err

    def test_no_tool_output_means_no_warning(self, capsys, monkeypatch):
        """Nothing was retrieved, so there is nothing to check against."""
        agent = FakeAgent()
        chunks = [(Chunk("just prose `with a quoted span here`"), {"langgraph_node": "model"})]
        monkeypatch.setattr(agent, "stream", lambda p, stream_mode=None: iter(chunks))

        cli.ask(agent, [], "why?", stream=True, check=True)
        assert "do not appear" not in capsys.readouterr().err

    def test_flag_is_parsed(self):
        assert cli.build_parser().parse_args(["--no-verify", "q"]).no_verify is True
        assert cli.build_parser().parse_args(["q"]).no_verify is False


class TestErrorHints:
    """A hint should point at the actual problem, not a plausible-sounding one."""

    def test_connection_errors_suggest_starting_ollama(self):
        hint = cli._connection_hint(ConnectionError("connection refused"), "m", "url")
        assert "ollama serve" in hint

    def test_missing_model_suggests_pulling_it(self):
        hint = cli._connection_hint(RuntimeError("model not found"), "qwen3", "url")
        assert "ollama pull qwen3" in hint

    def test_unrelated_errors_get_no_hint(self):
        assert cli._connection_hint(ValueError("bad tool schema"), "m", "url") is None

    def test_unrelated_error_does_not_blame_ollama(self, capsys):
        cli._report(ValueError("internal bug"), "m", "http://x")
        err = capsys.readouterr().err
        assert "internal bug" in err
        assert "ollama" not in err.lower()


class TestInteractive:
    def test_exit_word_ends_the_session(self, monkeypatch, capsys):
        monkeypatch.setattr("builtins.input", lambda _: "exit")
        agent = FakeAgent()
        assert cli.interactive(agent, "m", "url", stream=False) == 0
        assert agent.seen == []

    def test_eof_ends_the_session(self, monkeypatch):
        def raise_eof(_):
            raise EOFError

        monkeypatch.setattr("builtins.input", raise_eof)
        assert cli.interactive(FakeAgent(), "m", "url", stream=False) == 0

    def test_blank_input_does_not_call_the_agent(self, monkeypatch):
        answers = iter(["", "   ", "exit"])
        monkeypatch.setattr("builtins.input", lambda _: next(answers))
        agent = FakeAgent()
        cli.interactive(agent, "m", "url", stream=False)
        assert agent.seen == []

    def test_an_error_does_not_end_the_session(self, monkeypatch, capsys):
        answers = iter(["first", "exit"])
        monkeypatch.setattr("builtins.input", lambda _: next(answers))

        agent = FakeAgent()
        monkeypatch.setattr(agent, "invoke", lambda p: 1 / 0)
        assert cli.interactive(agent, "m", "url", stream=False) == 0
        assert "Agent error" in capsys.readouterr().err

    def test_context_carries_across_turns(self, monkeypatch):
        answers = iter(["what broke?", "and why?", "exit"])
        monkeypatch.setattr("builtins.input", lambda _: next(answers))
        agent = FakeAgent()
        cli.interactive(agent, "m", "url", stream=False)
        assert agent.seen[-1][0] == ("user", "what broke?")
        assert agent.seen[-1][-1] == ("user", "and why?")
