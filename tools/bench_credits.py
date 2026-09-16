"""Measure what each AI task really costs, and check the credit price against it.

`credits.TASK_PROFILES` claims a token cost per task.  Those numbers decide what
a customer is charged, so they have to come from observation rather than from a
plausible guess, and they have to be re-checkable when a prompt, a model or a
corpus changes.  This is that measurement.

The harness runs the **real task functions** (`llm.summarize`,
`llm.rewrite_decompilation`, and the rest) over real decompiled C, through the
**real sink** the server installs in production (`llm.recording_usage`), and
records the token counts the endpoint itself reported.  Nothing is estimated and
nothing is re-implemented: if this disagrees with the catalog, the catalog is
what is wrong.

Usage
-----

    .venv/bin/python tools/bench_credits.py --sample 8
    .venv/bin/python tools/bench_credits.py --sample 20 --json out.json
    .venv/bin/python tools/bench_credits.py --compare .scratch/bench-credits.json

Comparing models, including across providers, is ``--target`` repeated.  Each
is ``label=model@endpoint[,key=path]``, and the label is what names the column,
because the same model id is served by several providers at different prices::

    .venv/bin/python tools/bench_credits.py --sample 8 \
        --target "flash=deepseek-flash@https://api.deepseek.com,key=~/.secrets/deepseek.txt" \
        --target "or-qwen=qwen/qwen3.8-27b@https://openrouter.ai/api/v1,key=~/.secrets/openrouter"

The comparison is per task rather than per model, because the thinking ratio is
task-dependent: a model can be cheap on triage and ruinous on a whole-function
rewrite, and an average hides the case that decides whether it can be the bulk
generator.  The rewrite is also read against published per-function costs
(:data:`PUBLISHED_ANCHORS`), which is where the local numbers meet the outside
ones.

The endpoint is the normal bridge configuration (`REPORTAL_LLM_ENDPOINT`,
`REPORTAL_LLM_API_KEY`, `REPORTAL_LLM_MODEL`), so this measures whatever the
install is actually pointed at.  `--key-file` reads the key from a file instead
of the environment, which is how it runs against a local secret without the key
reaching the shell history or a log.

What it reports
---------------

Per task: the median and p90 of the prompt and completion tokens the endpoint
counted, what that costs at the catalog's rates, what the catalog currently
charges, and the ratio between them.  A task whose measured cost exceeds its
charge is flagged: that is the case where reportal sells a task for less than
it pays, and it is the reason this file exists.

Reasoning models
----------------

A model that reasons before answering bills the reasoning as completion tokens.
The run records `reasoning_tokens` separately where the endpoint reports them,
because a task that looks cheap in visible output can be expensive in total, and
the credit price has to follow the total.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import statistics
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reportal import credits as credits_mod
from reportal import llm

ROOT = Path(__file__).resolve().parent.parent

# Where the reversed corpus lives.  The same project the SPA smoke seeds from,
# so the measurement and the browser gate describe the same code.
DEFAULT_CORPUS = ROOT.parent / "rebrew-projects" / "notepad-rebrew" / "src"

# Bounds on a sampled function.  Below the floor there is nothing to summarize;
# above the ceiling one outlier would dominate a small sample's median.
MIN_SOURCE_CHARS = 100
MAX_SOURCE_CHARS = 20_000

# Where a run is written when `--json` names no path.
DEFAULT_REPORT = ROOT / ".scratch" / "bench-credits.json"


def _say(line: str = "") -> None:
    """One line of report output.  `sys.stdout.write` is the tools convention."""
    sys.stdout.write(f"{line}\n")


@dataclass
class Observation:
    """One completed task call, as the endpoint reported it."""

    task: str
    source_chars: int
    prompt_tokens: int
    completion_tokens: int
    reasoning_tokens: int
    seconds: float
    model: str


@dataclass
class TaskResult:
    """Every observation of one task, and what they say about its price."""

    task: str
    observations: list[Observation] = field(default_factory=list)
    failures: int = 0

    def _median(self, pick: str) -> float:
        values = [float(getattr(o, pick)) for o in self.observations]
        return float(statistics.median(values)) if values else 0.0

    def _p90(self, pick: str) -> float:
        values = sorted(float(getattr(o, pick)) for o in self.observations)
        return values[int(len(values) * 0.9)] if values else 0.0

    def measured_cogs_usd(self) -> float:
        """What the median call costs at the catalog's own model rates."""
        from reportal import plans

        input_rate, output_rate = plans.MODEL_RATES.get(
            plans.COST_MODEL, max(plans.MODEL_RATES.values(), key=lambda pair: pair[1])
        )
        return (
            self._median("prompt_tokens") * input_rate / 1e6
            + self._median("completion_tokens") * output_rate / 1e6
        )

    def charged_usd(self) -> float:
        """What the catalog currently charges for one standard call."""
        return credits_mod.base_credits(self.task) * credits_mod.credit_cogs_usd()

    def describe(self) -> dict[str, Any]:
        profile = credits_mod.TASK_PROFILES.get(self.task)
        measured = self.measured_cogs_usd()
        charged = self.charged_usd()
        return {
            "task": self.task,
            "calls": len(self.observations),
            "failures": self.failures,
            "prompt_tokens_median": self._median("prompt_tokens"),
            "prompt_tokens_p90": self._p90("prompt_tokens"),
            "completion_tokens_median": self._median("completion_tokens"),
            "completion_tokens_p90": self._p90("completion_tokens"),
            "reasoning_tokens_median": self._median("reasoning_tokens"),
            "seconds_median": round(self._median("seconds"), 2),
            "profile_prompt_tokens": profile.input_tokens if profile else None,
            "profile_completion_tokens": profile.output_tokens if profile else None,
            "measured_cogs_usd": round(measured, 6),
            "charged_credits": credits_mod.base_credits(self.task),
            "charged_usd": round(charged, 6),
            # Above 1.0 the task is sold for less than it costs to serve.
            "cost_over_charge": round(measured / charged, 3) if charged else None,
        }


def sample_sources(corpus: Path, count: int) -> list[str]:
    """Read *count* decompiled functions, evenly spread across the corpus.

    Spread rather than the first N, because a directory listing is alphabetical
    and the first files would over-represent one part of one binary.
    """
    paths = sorted(corpus.rglob("*.c"))
    bodies: list[str] = []
    for path in paths:
        text = path.read_text(errors="replace")
        if MIN_SOURCE_CHARS < len(text) < MAX_SOURCE_CHARS:
            bodies.append(text)
    if not bodies:
        raise SystemExit(f"no usable sources under {corpus}")
    if count >= len(bodies):
        return bodies
    step = len(bodies) / count
    return [bodies[int(index * step)] for index in range(count)]


def _reasoning_of(completion: Any) -> int:
    """The reasoning tokens an endpoint reports, or 0 when it reports none.

    Reasoning is billed as completion, so it is already inside the total the
    sink records.  It is captured separately because a model that thinks before
    answering can spend most of a task's output on tokens the user never sees,
    and a price set from visible output alone would be badly wrong.
    """
    usage = getattr(completion, "usage", None)
    details = getattr(usage, "completion_tokens_details", None)
    return int(getattr(details, "reasoning_tokens", 0) or 0)


@contextlib.contextmanager
def _watch_reasoning(into: list[int]) -> Iterator[None]:
    """Record the reasoning split of each completion inside the block.

    `llm._report_usage` already receives the raw completion object, so wrapping
    it reads the split without a second request and without the production sink
    growing a field only this harness wants.
    """
    original = llm._report_usage

    def wrapper(completion: Any, model: str) -> None:
        into.append(_reasoning_of(completion))
        original(completion, model)

    llm._report_usage = wrapper  # type: ignore[assignment]
    try:
        yield
    finally:
        llm._report_usage = original  # type: ignore[assignment]


# The tasks this harness can drive, each as the real call a route makes.
RUNNERS: dict[str, Any] = {
    credits_mod.TASK_SUMMARY: lambda code: llm.summarize(code),
    credits_mod.TASK_COMMENTS: lambda code: llm.inline_comments(code),
    credits_mod.TASK_TYPES: lambda code: llm.suggest_types(code),
    credits_mod.TASK_DECOMPILE: lambda code: llm.rewrite_decompilation(code),
    credits_mod.TASK_RENAMES: lambda code: llm.rename_suggestions(code),
    credits_mod.TASK_TRIAGE: lambda code: llm.function_triage(code),
    credits_mod.TASK_THREAT: lambda code: llm.threat_narrative(code),
}


def run_task(task: str, sources: list[str], *, verbose: bool) -> TaskResult:
    """Run one task over every sampled source, recording what the endpoint says."""
    result = TaskResult(task=task)
    runner = RUNNERS[task]
    for index, code in enumerate(sources, start=1):
        captured: list[tuple[int, int, str]] = []

        def sink(
            prompt: int,
            completion: int,
            model: str,
            into: list[tuple[int, int, str]] = captured,
        ) -> None:
            into.append((prompt, completion, model))

        # The real production sink, so the harness measures the same path the
        # server meters rather than a parallel one.
        reasoning: list[int] = []
        started = time.monotonic()
        try:
            with llm.recording_usage(sink), _watch_reasoning(reasoning):
                runner(code)
        except Exception as exc:  # a provider error is a data point
            result.failures += 1
            # The first failure is always reported, quiet or not: a provider
            # that refuses every call (no credit, wrong model id, a rate limit)
            # would otherwise show up only as an empty column.
            if verbose or result.failures == 1:
                detail = str(exc).replace("\n", " ")[:200]
                _say(f"    [{index}] {task}: failed ({type(exc).__name__}: {detail})")
            continue
        elapsed = time.monotonic() - started
        if not captured:
            result.failures += 1
            if verbose or result.failures == 1:
                _say(
                    f"    [{index}] {task}: the call returned no usage block,"
                    " so it cannot be priced"
                )
            continue
        prompt, completion, model = captured[-1]
        # The reasoning split is not on the sink (it is not billable separately),
        # so it is read from the raw completion where the endpoint reports it.
        result.observations.append(
            Observation(
                task=task,
                source_chars=len(code),
                prompt_tokens=prompt,
                completion_tokens=completion,
                reasoning_tokens=reasoning[-1] if reasoning else 0,
                seconds=elapsed,
                model=model,
            )
        )
        if verbose:
            thought = f" ({reasoning[-1]} thinking)" if reasoning and reasoning[-1] else ""
            _say(f"    [{index}] {task}: {prompt} in, {completion} out{thought}, {elapsed:.1f}s")
    return result


@dataclass(frozen=True)
class Target:
    """One model to measure: where it lives and what to call it."""

    label: str
    endpoint: str
    model: str
    key_file: Path | None = None

    @classmethod
    def parse(cls, spec: str) -> Target:
        """Read a ``label=model@endpoint[,key=path]`` target specification.

        A label rather than a bare model name because the same model id is
        served by several providers at different prices, and the comparison is
        only readable when each column says which one it was.
        """
        label, _, rest = spec.partition("=")
        if not rest:
            # No explicit label: name the column after the model rather than the
            # whole spec, so an unlabelled target still reads in a table.
            rest = spec
            label = spec.partition("@")[0].partition(",key=")[0]
        body, _, key = rest.partition(",key=")
        model, _, endpoint = body.partition("@")
        if not model or not endpoint:
            raise SystemExit(
                f"bad --target {spec!r}; expected label=model@https://host[,key=/path]"
            )
        return cls(
            label=label.strip(),
            endpoint=endpoint.strip(),
            model=model.strip(),
            key_file=Path(key).expanduser() if key else None,
        )


def _configure(target: Target) -> None:
    """Point the bridge at one target, replacing whatever was set before.

    Assignment rather than `setdefault`: a comparison run configures several
    targets in one process, and a default that stuck would silently measure the
    first endpoint under every later label.
    """
    if target.key_file is not None:
        os.environ["REPORTAL_LLM_API_KEY"] = target.key_file.read_text().strip()
    os.environ["REPORTAL_LLM_ENDPOINT"] = target.endpoint
    os.environ["REPORTAL_LLM_MODEL"] = target.model
    llm.set_client(None)


def _print_table(results: list[TaskResult]) -> None:
    """The measurement, and whether the price covers it."""
    _say("")
    _say(
        f"{'task':18} {'calls':>5} {'in':>7} {'out':>7} {'p90 out':>8} "
        f"{'cost':>9} {'charge':>9} {'ratio':>7}"
    )
    _say("-" * 80)
    for result in results:
        row = result.describe()
        if not row["calls"]:
            _say(f"{result.task:18} {'0':>5}  (no successful calls)")
            continue
        flag = " OVER" if (row["cost_over_charge"] or 0) > 1 else ""
        _say(
            f"{result.task:18} {row['calls']:>5} "
            f"{row['prompt_tokens_median']:>7.0f} {row['completion_tokens_median']:>7.0f} "
            f"{row['completion_tokens_p90']:>8.0f} "
            f"${row['measured_cogs_usd']:>8.5f} ${row['charged_usd']:>8.5f} "
            f"{row['cost_over_charge']:>6.2f}x{flag}"
        )


def _print_verdict(results: list[TaskResult]) -> int:
    """Name every task sold below cost; the exit status follows."""
    underpriced = [
        result
        for result in results
        if result.observations and result.measured_cogs_usd() > result.charged_usd()
    ]
    _say("")
    measured = [result for result in results if result.observations]
    if not measured:
        # Zero calls is not a pass.  Saying "every task is solvent" here would
        # turn a provider outage into a green result, which is the one failure
        # mode a pricing gate must not have.
        failed = sum(result.failures for result in results)
        _say(f"No task produced a usable call ({failed} failure(s)); nothing was measured.")
        return 2
    if not underpriced:
        _say("Every measured task is charged at or above what it costs to serve.")
        return 0
    _say("Underpriced tasks (measured cost above the charged price):")
    for result in underpriced:
        row = result.describe()
        needed = credits_mod.base_credits(result.task) * (row["cost_over_charge"] or 1)
        _say(
            f"  {result.task}: costs {row['cost_over_charge']}x its charge; "
            f"raise from {row['charged_credits']} to at least {needed:.0f} credits"
        )
    return 1


def _compare(previous: Path, results: list[TaskResult]) -> None:
    """Show the drift against an earlier run, which is what makes this a benchmark."""
    try:
        stored = json.loads(previous.read_text())
    except (OSError, ValueError) as exc:
        _say(f"could not read {previous}: {exc}")
        return
    before = {row["task"]: row for row in stored.get("tasks", [])}
    _say("")
    _say(f"Drift against {previous.name} ({stored.get('recorded_at', 'unknown date')}):")
    for result in results:
        row = result.describe()
        old = before.get(result.task)
        if old is None or not row["calls"]:
            continue
        delta = row["completion_tokens_median"] - old["completion_tokens_median"]
        share = (
            (delta / old["completion_tokens_median"] * 100)
            if old["completion_tokens_median"]
            else 0.0
        )
        _say(
            f"  {result.task:18} output {old['completion_tokens_median']:.0f}"
            f" -> {row['completion_tokens_median']:.0f} ({share:+.0f}%)"
        )


# Published per-function costs for a whole-function rewrite, as external
# anchors a local run can be read against.  Source: DecBench's own economics
# table (see ~/Desktop/ai-decomp `wiki/decomp/benchmarks.md`), where the two
# coding agents are the only backends carrying a dollar figure.  They are
# agent loops rather than one completion, which is exactly the point: the
# same task costs two orders of magnitude more when it is driven as a
# multi-turn agent than as a single prompt.
PUBLISHED_ANCHORS: tuple[tuple[str, float, str], ...] = (
    ("Claude Code (opus-4-8) agent loop", 1.92, "DecBench, 108 s median"),
    ("Codex (gpt-5.6-sol) agent loop", 0.68, "DecBench, 135 s median"),
)


def _compare_targets(runs: list[tuple[Target, list[TaskResult]]]) -> None:
    """Put every measured model side by side, per task, cheapest column first.

    The comparison is per task rather than per model overall, because the
    thinking ratio is task-dependent: a model can be cheap on triage and
    ruinous on a rewrite, and an average would hide exactly the case that
    decides whether it can be the bulk generator.
    """
    if len(runs) < 2:
        return
    labels = [target.label for target, _ in runs]
    tasks = sorted({result.task for _, results in runs for result in results})
    width = max(12, max(len(label) for label in labels) + 2)

    _say("")
    _say("Cost per call, by model (USD at the catalog's rates):")
    _say("")
    _say(f"{'task':18}" + "".join(f"{label:>{width}}" for label in labels) + f"{'spread':>9}")
    _say("-" * (18 + width * len(labels) + 9))
    for task in tasks:
        cells: list[str] = []
        costs: list[float] = []
        for _, results in runs:
            found = next((r for r in results if r.task == task and r.observations), None)
            if found is None:
                cells.append(f"{'-':>{width}}")
                continue
            cost = found.measured_cogs_usd()
            costs.append(cost)
            cells.append(f"{'$' + format(cost, '.5f'):>{width}}")
        spread = f"{max(costs) / min(costs):.1f}x" if len(costs) > 1 and min(costs) else "-"
        _say(f"{task:18}" + "".join(cells) + f"{spread:>9}")

    _say("")
    _say("Thinking ratio (billed output / visible answer), by model:")
    _say("")
    _say(f"{'task':18}" + "".join(f"{label:>{width}}" for label in labels))
    _say("-" * (18 + width * len(labels)))
    for task in tasks:
        cells = []
        for _, results in runs:
            found = next((r for r in results if r.task == task and r.observations), None)
            if found is None:
                cells.append(f"{'-':>{width}}")
                continue
            total = found._median("completion_tokens")
            think = found._median("reasoning_tokens")
            visible = total - think
            cells.append(f"{format(total / visible, '.1f') + 'x' if visible else 'n/a':>{width}}")
        _say(f"{task:18}" + "".join(cells))


def _print_anchors(runs: list[tuple[Target, list[TaskResult]]]) -> None:
    """Read the measured rewrite cost against published per-function figures."""
    measured: list[tuple[str, float]] = []
    for target, results in runs:
        found = next(
            (r for r in results if r.task == credits_mod.TASK_DECOMPILE and r.observations),
            None,
        )
        if found is not None:
            measured.append((target.label, found.measured_cogs_usd()))
    if not measured:
        return
    _say("")
    _say("Whole-function rewrite against published per-function costs:")
    for label, cost in sorted(measured, key=lambda pair: pair[1]):
        _say(f"  {label:32} ${cost:>8.5f}  (measured here, one completion)")
    for label, cost, note in PUBLISHED_ANCHORS:
        cheapest = min(cost for _, cost in measured)
        _say(f"  {label:32} ${cost:>8.5f}  ({note}; {cost / cheapest:,.0f}x)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=int, default=6, help="functions per task (default 6)")
    parser.add_argument(
        "--tasks",
        default="",
        help="comma-separated task names (default: every task with a runner)",
    )
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        metavar="LABEL=MODEL@ENDPOINT[,key=PATH]",
        help=(
            "a model to measure; repeat to compare several across providers, "
            "e.g. --target flash=deepseek-flash@https://api.deepseek.com,key=~/.secrets/deepseek.txt"
        ),
    )
    parser.add_argument(
        "--endpoint", default="https://api.deepseek.com", help="chat-completions base URL"
    )
    parser.add_argument("--model", default="deepseek-flash")
    parser.add_argument("--key-file", type=Path, default=None, help="file holding the API key")
    parser.add_argument(
        "--json",
        type=Path,
        nargs="?",
        const=DEFAULT_REPORT,
        default=None,
        help=f"write the run as JSON (default path {DEFAULT_REPORT})",
    )
    parser.add_argument(
        "--compare", type=Path, default=None, help="an earlier JSON run to diff against"
    )
    parser.add_argument("--quiet", action="store_true", help="suppress per-call lines")
    args = parser.parse_args()

    targets = (
        [Target.parse(spec) for spec in args.target]
        if args.target
        else [
            Target(
                label=args.model,
                endpoint=args.endpoint,
                model=args.model,
                key_file=args.key_file,
            )
        ]
    )

    names = [name.strip() for name in args.tasks.split(",") if name.strip()] or list(RUNNERS)
    unknown = [name for name in names if name not in RUNNERS]
    if unknown:
        _say(f"unknown task(s): {', '.join(unknown)}")
        _say(f"known: {', '.join(RUNNERS)}")
        return 2

    sources = sample_sources(args.corpus, args.sample)
    runs: list[tuple[Target, list[TaskResult]]] = []
    status = 0
    for target in targets:
        _configure(target)
        if not llm.get_client().available():
            _say(f"{target.label}: no endpoint configured (pass key= in --target)")
            return 2
        _say("")
        _say(
            f"Measuring {len(names)} task(s) over {len(sources)} function(s) "
            f"against {target.model} at {target.endpoint}  [{target.label}]"
        )
        results = []
        for task in names:
            _say(f"  {task} ...")
            results.append(run_task(task, sources, verbose=not args.quiet))
        _print_table(results)
        if args.compare is not None and len(targets) == 1:
            _compare(args.compare, results)
        # The verdict is per model: a task can be solvent on one and not another,
        # and the exit status has to fail if any measured target is underwater.
        status |= _print_verdict(results)
        runs.append((target, results))

    _compare_targets(runs)
    _print_anchors(runs)

    if args.json is not None:
        payload = {
            "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "sample": len(sources),
            "corpus": str(args.corpus),
            "credit_cogs_usd": credits_mod.credit_cogs_usd(),
            "runs": [
                {
                    "label": target.label,
                    "model": target.model,
                    "endpoint": target.endpoint,
                    "tasks": [result.describe() for result in results],
                }
                for target, results in runs
            ],
            # The single-target shape the earlier runs used, kept so `--compare`
            # reads a file this version wrote as well as one the last did.
            "model": runs[0][0].model,
            "endpoint": runs[0][0].endpoint,
            "tasks": [result.describe() for result in runs[0][1]],
        }
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(payload, indent=2) + "\n")
        _say(f"\nWrote {args.json}")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
