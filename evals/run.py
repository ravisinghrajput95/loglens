"""Run the evaluation suite.

    python -m evals.run                     tool correctness + verifier bench
    python -m evals.run --live              also run a model against every case
    python -m evals.run --live -m llama3.2  a specific model
    python -m evals.run --live --repeat 3   repeat runs, to see variance

Offline mode needs no model and is deterministic, so CI can gate on it. Live
mode reports the model it used, because a number without a model name attached
means nothing.
"""

import argparse
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

from .dataset import BY_NAME, CASES
from .formats import run as run_formats
from .score import AnswerResult, score_answer, score_tools, write_log
from .verifier_bench import BLIND_SPOTS, run_blind_spots
from .verifier_bench import run as run_verifier_bench


def run_offline(cases) -> tuple[int, int, list]:
    results = [score_tools(case) for case in cases]
    passed = sum(r.passed for r in results)
    total = sum(r.total for r in results)
    return passed, total, results


def run_live(cases, model: str, repeat: int) -> list[AnswerResult]:
    """Run the agent against each case. Requires a reachable Ollama."""
    from loglens.agent import build_agent

    agent = build_agent(model=model)
    results: list[AnswerResult] = []

    with tempfile.TemporaryDirectory() as tmp:
        for case in cases:
            path = write_log(case, Path(tmp))
            question = f"{case.question} The file is at {path}."

            for _ in range(repeat):
                start = time.perf_counter()
                try:
                    state = agent.invoke({"messages": [("user", question)]})
                except Exception as exc:  # noqa: BLE001 — recorded, not hidden
                    print(f"  {case.name}: could not run — {exc}", file=sys.stderr)
                    continue
                elapsed = time.perf_counter() - start

                tool_outputs = [
                    str(m.content)
                    for m in state["messages"]
                    if getattr(m, "type", None) == "tool"
                ]
                calls = [
                    tc["name"]
                    for m in state["messages"]
                    for tc in (getattr(m, "tool_calls", None) or [])
                ]
                answer = state["messages"][-1].content

                scored = score_answer(case, answer, tool_outputs, model)
                scored.tool_calls = calls
                scored.seconds = elapsed
                results.append(scored)
                mark = "ok " if scored.ok else "FAIL"
                print(
                    f"  {mark} {case.name:<28} {scored.passed}/{scored.total} checks  "
                    f"coverage {scored.coverage * 100:3.0f}%  "
                    f"fabricated {scored.fabricated}  "
                    f"{len(calls)} calls  {elapsed:.0f}s",
                    flush=True,
                )

    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="evals.run", description=__doc__)
    parser.add_argument("--live", action="store_true", help="Also run a real model.")
    parser.add_argument("-m", "--model", default="gemma4")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument(
        "--ablate",
        action="store_true",
        help="Run the hostile log with the safety layer on and off, and compare.",
    )
    parser.add_argument("--case", action="append", help="Run only these cases.")
    parser.add_argument("--json", type=Path, help="Write results as JSON.")
    args = parser.parse_args(argv)

    cases = [BY_NAME[name] for name in args.case] if args.case else CASES

    print(f"Tool correctness — {len(cases)} cases, no model required")
    passed, total, case_results = run_offline(cases)
    for result in case_results:
        mark = "ok " if result.ok else "FAIL"
        print(f"  {mark} {result.case:<28} {result.passed}/{result.total}")
        for check in result.checks:
            if not check.passed:
                print(f"       - {check.name}: {check.detail}")
    print(f"  => {passed}/{total} checks passed\n")

    print("Format coverage — one line per real-world corpus")
    format_results = run_formats()
    bad = [(name, detail) for name, ok, detail in format_results if not ok]
    for name, detail in bad:
        print(f"  FAIL {name}: {detail}")
    print(f"  => {len(format_results) - len(bad)}/{len(format_results)} formats recognised\n")

    print("Verifier precision and recall — labelled honest vs fabricated answers")
    bench = run_verifier_bench()
    print(
        f"  precision {bench.precision:.2f}  recall {bench.recall:.2f}  "
        f"f1 {bench.f1:.2f}   "
        f"(tp {bench.true_positive} fp {bench.false_positive} "
        f"tn {bench.true_negative} fn {bench.false_negative})"
    )
    for miss in bench.misses:
        print(f"    MISSED: {miss}")
    for alarm in bench.false_alarms:
        print(f"    FALSE ALARM: {alarm}")

    slipped = run_blind_spots()
    print(
        f"  Known blind spots: {len(slipped)}/{len(BLIND_SPOTS)} wrong answers pass "
        "unflagged. These are not counted above."
    )
    for why in slipped:
        print(f"    UNCAUGHT: {why}")
    print()

    live_results: list[AnswerResult] = []
    if args.live:
        print(f"Answer quality — model {args.model}, {args.repeat} run(s) per case")
        live_results = run_live(cases, args.model, args.repeat)
        if live_results:
            checks_passed = sum(r.passed for r in live_results)
            checks_total = sum(r.total for r in live_results)
            fabricated = sum(r.fabricated for r in live_results)
            coverages = [r.coverage for r in live_results]
            times = [r.seconds for r in live_results]
            print(
                f"  => {checks_passed}/{checks_total} checks, "
                f"{fabricated} fabricated citations, "
                f"median coverage {statistics.median(coverages) * 100:.0f}%, "
                f"median {statistics.median(times):.0f}s"
            )

    if args.ablate:
        from .ablation import run as run_ablation

        print(f"Ablation — hostile log, model {args.model}")
        for run in run_ablation(args.model):
            print(f"  {run.label:<14} {run.verdict}")
            if run.tool_calls:
                print(f"                 tools: {', '.join(run.tool_calls)}")
        print()

    if args.json:
        args.json.write_text(
            json.dumps(
                {
                    "tool_checks": {"passed": passed, "total": total},
                    "verifier": {
                        "precision": bench.precision,
                        "recall": bench.recall,
                        "f1": bench.f1,
                    },
                    "live": [
                        {
                            "case": r.case,
                            "model": r.model,
                            "passed": r.passed,
                            "total": r.total,
                            "coverage": r.coverage,
                            "fabricated": r.fabricated,
                            "poisoned": r.poisoned,
                            "tool_calls": r.tool_calls,
                            "seconds": r.seconds,
                        }
                        for r in live_results
                    ],
                },
                indent=2,
            )
        )

    failed_formats = bool(bad)
    failed_offline = passed != total
    failed_verifier = bench.false_negative > 0 or bench.false_positive > 0
    return 1 if (failed_offline or failed_verifier or failed_formats) else 0


if __name__ == "__main__":
    raise SystemExit(main())
