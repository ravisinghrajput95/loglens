"""A browser view of the deterministic report.

Everything here is a second presentation of `analysis.py`. No fact is computed
in this file — it reads the same structured results the CLI does, so the two
cannot disagree about a count. That is the reason the UI could be added without
touching anything else: `analysis.py` returns dataclasses and holds no state,
and `parser` and `analysis` between them pull in none of the terminal rendering,
none of the tool wrappers, and no LangChain.

Two rules this file inherits and must not quietly break:

  - An error rate is not shown for a file whose format carries no severity.
    Reporting "0.0% errors" for a log full of failures is the confident wrong
    answer the CLI already refuses to give.
  - Log content is attacker-influenced. It is rendered as text, never as
    markup. `unsafe_allow_html` must not appear in this file — a browser is
    the one surface where a crafted log line becomes executable.

Run it with `loglens-ui` (see `ui_launch.py`), or `streamlit run loglens/ui.py`.
"""

from __future__ import annotations

import os

import streamlit as st

# Absolute imports, not relative: Streamlit executes this file as a script, so
# it has no parent package and `from . import analysis` raises ImportError.
from loglens import analysis
from loglens.parser import LoadResult, load_entries, load_many

# Streamlit reruns this module top to bottom on every interaction, so anything
# expensive has to be cached. A 42 MB file takes about 30 seconds to parse.
CACHE_TTL = 3600


def _fingerprint(paths: tuple[str, ...]) -> tuple[tuple[str, float, int], ...]:
    """Identity of the files on disk, so an edited file re-parses."""
    out = []
    for path in paths:
        try:
            stat = os.stat(path)
            out.append((path, stat.st_mtime, stat.st_size))
        except OSError:
            out.append((path, 0.0, -1))
    return tuple(out)


@st.cache_data(show_spinner="Parsing…", ttl=CACHE_TTL)
def _load(paths: tuple[str, ...], _fp) -> LoadResult:
    """Parse, cached on the files' identity rather than on the path alone."""
    if len(paths) == 1:
        return load_entries(paths[0])
    return load_many(list(paths))


def _levels_frame(result: LoadResult) -> dict[str, list]:
    order = ["FATAL", "ERROR", "WARN", "INFO", "DEBUG", "UNKNOWN"]
    present = [lvl for lvl in order if result.total_by_level.get(lvl)]
    return {
        "level": present,
        "entries": [result.total_by_level[lvl] for lvl in present],
    }


def _service_rows(summary: analysis.Summary) -> list[dict]:
    rows = []
    for name, counts in summary.by_service.items():
        failing = counts.get("ERROR", 0) + counts.get("FATAL", 0)
        rows.append(
            {
                "service": name,
                "failing": failing,
                "total": sum(counts.values()),
                **{level.lower(): n for level, n in sorted(counts.items())},
            }
        )
    # Failures first, then volume, then name — the same reading order the
    # terminal report uses, so the two do not rank services differently.
    return sorted(rows, key=lambda r: (-r["failing"], -r["total"], r["service"]))


def _entry_rows(entries) -> list[dict]:
    return [
        {
            "line": e.citation_id,
            "time": e.timestamp.strftime("%Y-%m-%d %H:%M:%S") if e.timestamp else "",
            "level": ("~" if e.level_inferred else "") + e.level,
            "service": e.service or "",
            "message": e.message,
            "suspicious": "!!" if e.suspicious else "",
            "source": e.source or "",
        }
        for e in entries
    ]


def _header(result: LoadResult, summary: analysis.Summary) -> None:
    cols = st.columns(4)
    cols[0].metric("Entries", f"{result.total_entries:,}")

    if result.has_severity:
        cols[1].metric("Error rate", f"{result.error_rate:.1f}%")
    else:
        # The whole point of the CLI's behaviour here: a rate this file cannot
        # support is not shown at all.
        cols[1].metric("Error rate", "—", help="This format carries no severity field.")

    failing = sum(
        1
        for counts in summary.by_service.values()
        if counts.get("ERROR", 0) or counts.get("FATAL", 0)
    )
    cols[2].metric("Services failing", f"{failing}/{len(summary.by_service)}")

    if summary.first_seen and summary.last_seen:
        span = summary.last_seen - summary.first_seen
        cols[3].metric("Span", str(span).split(".")[0])
    else:
        cols[3].metric("Span", "—")

    st.caption(f"Formats detected: {result.format_summary}")


def _caveats(result: LoadResult) -> None:
    notes = []
    if not result.has_severity:
        notes.append(
            "This log carries no severity field, so no error rate is computed. "
            "The CLI's `--infer-severity` guesses one from wording and marks every "
            "guess with `~`."
        )
    if result.truncated:
        notes.append(
            f"Detail was capped: counts cover all {result.total_entries:,} entries, "
            f"but only the most recent {len(result.entries):,} are listed below."
        )
    if result.redactions:
        listed = ", ".join(f"{k} x{v}" for k, v in sorted(result.redactions.items()))
        notes.append(f"Redacted before analysis: {listed}.")
    if result.skipped:
        notes.append(f"{result.skipped:,} line(s) did not parse and are not counted.")

    for note in notes:
        st.info(note)

    if result.suspicious:
        st.warning(
            f"{result.suspicious} line(s) look like a prompt-injection attempt and are "
            "marked `!!` below. An attempt is itself a finding — the lines are shown, "
            "not dropped."
        )


def render(result: LoadResult) -> None:
    """The whole page, given an already-parsed file."""
    summary = analysis.summarize(result.entries, result.skipped)

    _header(result, summary)
    _caveats(result)

    st.subheader("Levels")
    st.bar_chart(_levels_frame(result), x="level", y="entries", horizontal=True)

    st.subheader("Services")
    st.dataframe(_service_rows(summary), width="stretch", hide_index=True)

    st.subheader("Error patterns")
    groups = analysis.top_errors(result.entries, limit=20)
    if not groups:
        st.write("No ERROR or FATAL entries.")
    for group in groups:
        flag = "  ‼️" if group.example.suspicious else ""
        with st.expander(f"[{group.count}x] {group.signature}{flag}"):
            st.write(f"**Services:** {', '.join(group.services) or 'unknown'}")
            if group.exceptions:
                st.write(f"**Exception:** {group.exceptions[0]}")
            st.write(f"**First seen at line** [L{group.example.citation_id}]")
            # st.code renders as text, never as markup.
            st.code(group.example.message, language=None)

    st.subheader("Traces containing failures")
    failing: dict[str, int] = {}
    for entry in result.entries:
        if entry.is_failure and entry.trace_id:
            failing[entry.trace_id] = failing.get(entry.trace_id, 0) + 1

    if not failing:
        st.write("No trace_id on any failing entry — a request cannot be reconstructed.")
    else:
        ranked = sorted(failing, key=lambda t: -failing[t])
        chosen = st.selectbox(
            "Trace", ranked, format_func=lambda t: f"{t}  ({failing[t]} failure(s))"
        )
        steps = analysis.trace_timeline(result.entries, chosen)
        st.dataframe(
            [
                {
                    "gap": "start" if s.gap_ms is None else f"+{s.gap_ms:,.0f}ms",
                    "line": s.entry.citation_id,
                    "level": s.entry.level,
                    "service": s.entry.service or "",
                    "message": s.entry.message,
                    "failure": "<--" if s.entry.is_failure else "",
                }
                for s in steps
            ],
            width="stretch",
            hide_index=True,
        )

    st.subheader("Search")
    left, right = st.columns([3, 1])
    pattern = left.text_input("Message matches (regex)", key="pattern")
    level = right.selectbox("Level", ["any", "ERROR", "FATAL", "WARN", "INFO", "DEBUG"])

    try:
        hits, matched = analysis.search(
            result.entries,
            pattern=pattern or None,
            level=None if level == "any" else level,
            limit=500,
        )
    except analysis.UnsafePattern as exc:
        # A model-supplied or user-supplied regex with nested quantifiers is
        # refused rather than run: Python's re has no timeout.
        st.error(str(exc))
    else:
        st.write(
            f"{matched:,} match(es)"
            + (f", showing {len(hits):,}" if matched > len(hits) else "")
        )
        st.dataframe(_entry_rows(hits), width="stretch", hide_index=True)


# Streamlit owns the process it runs the script in, and under a test runner
# sys.argv belongs to the test runner rather than to us. The launcher puts the
# paths here instead, which is the one channel that means the same thing in
# both cases.
PATHS_ENV = "LOGLENS_UI_PATHS"


def initial_paths() -> str:
    """What to prefill the file box with."""
    return os.environ.get(PATHS_ENV) or "app.log"


def app() -> None:
    """Entry point Streamlit executes."""
    st.set_page_config(page_title="LogLens", page_icon="🔎", layout="wide")
    st.title("🔎 LogLens")
    st.caption(
        "Deterministic log triage. Every number here is computed in Python from "
        "the file — no model is involved."
    )

    raw = st.text_input(
        "Log file(s)",
        value=initial_paths(),
        help="One or more paths, space separated. Several files merge into one timeline.",
    )
    paths = tuple(p for p in raw.split() if p)
    if not paths:
        st.stop()

    missing = [p for p in paths if not os.path.exists(p)]
    if missing:
        st.error(f"No such file: {', '.join(missing)}")
        st.stop()

    render(_load(paths, _fingerprint(paths)))


if __name__ == "__main__":
    app()
