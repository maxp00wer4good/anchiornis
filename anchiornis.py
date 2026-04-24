"""Anchiornis v0.2 CLI for local IOC investigation.

This entrypoint loads `.env` once, allows ad-hoc CLI overrides, and then runs a
single IOC investigation through the LangGraph workflow.

Examples:
    python anchiornis.py --seed http://youtubeaccount.com --llm-provider none
    python anchiornis.py --seed http://youtubeaccount.com --llm-provider ollama \
        --llm-model llama3.1:8b --ollama-base-url http://host.docker.internal:11434
    python anchiornis.py --seed http://youtubeaccount.com --llm-provider anthropic \
        --llm-model claude-sonnet-4-6 --llm-final-summary
"""

from __future__ import annotations

import argparse
import os
from typing import Any

from dotenv import load_dotenv

from core.helpers import detect_type
from core.trace import write_execution_trace
from graph.workflow import build_investigation_workflow


__version__ = "0.2"


ANCHIORNIS_LOGO_TEMPLATE = r"""
      _                _     _                 _     
     / \   _ __   ___ | |__ (_) ___  _ __ _ __ (_)___ 
    / _ \ | '_ \ / __|| '_ \| |/ _ \| '__| '_ \| / __|
   / ___ \| | | | (__ | | | | | (_) | |  | | | | \__ \
  /_/   \_\_| |_|\___||_| |_|_|\___/|_|  |_| |_|_|___/

                     A N C H I O R N I S
                         v.{version}
                    ── Threat Intel ──
"""


def get_anchiornis_logo() -> str:
    """Return the Anchiornis ASCII logo with the current version injected."""
    return ANCHIORNIS_LOGO_TEMPLATE.format(version=__version__)


def _load_console():
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.progress import (
            BarColumn,
            Progress,
            SpinnerColumn,
            TextColumn,
            TimeElapsedColumn,
        )

        return Console, Panel, Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    except Exception:
        return None, None, None, None, None, None, None


def _strip_rich_markup(text: str) -> str:
    """Best-effort cleanup when rich is not installed."""
    return (
        text.replace("[bold cyan]", "")
        .replace("[/bold cyan]", "")
        .replace("[bold green]", "")
        .replace("[/bold green]", "")
        .replace("[bold blue]", "")
        .replace("[/bold blue]", "")
        .replace("[bold]", "")
        .replace("[/bold]", "")
    )


def _print_cli_header(console, Panel, seed: str, seed_type: str, args: argparse.Namespace) -> None:
    title = "Anchiornis IOC investigation"
    body = (
        f"[bold cyan]{get_anchiornis_logo()}[/bold cyan]\n"
        f"[bold]Seed[/bold]: {seed_type} {seed}\n"
        f"[bold]LLM provider[/bold]: {args.llm_provider or os.getenv('IOC_LLM_PROVIDER', 'env/default')}\n"
        f"[bold]Max iterations[/bold]: {args.max_iterations}\n"
        f"[bold]Trace JSON[/bold]: {'disabled' if args.no_trace else args.trace_dir}"
    )

    if console and Panel:
        console.print(Panel.fit(body, title=title, border_style="cyan"))
    else:
        print(f"\n== {title} v{__version__} ==")
        print(_strip_rich_markup(body))


def _print_cli_footer(console, Panel, trace_path, final_report: str) -> None:
    if console and Panel:
        if trace_path is not None:
            console.print(
                Panel.fit(
                    f"Trace JSON written to: [bold green]{trace_path}[/bold green]",
                    title="Trace",
                    border_style="green",
                )
            )

        console.print(
            Panel(
                final_report or "No final report generated.",
                title="Final summary",
                border_style="magenta",
            )
        )
        return

    if trace_path is not None:
        print(f"\nTrace JSON written to: {trace_path}")

    print("\n" + (final_report or "No final report generated."))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=f"Anchiornis v{__version__}: run a single IOC investigation workflow."
    )

    parser.add_argument("--version", action="version", version=f"Anchiornis v{__version__}")
    parser.add_argument("--seed", default="http://youtubeaccount.com", help="Seed observable to investigate")
    parser.add_argument("--max-iterations", type=int, default=12, help="Safety limit for workflow iterations")
    parser.add_argument(
        "--llm-provider",
        choices=["none", "ollama", "anthropic"],
        default=None,
        help="Override the semantic LLM provider for this run",
    )
    parser.add_argument("--llm-model", default=None, help="Override IOC_LLM_MODEL for this run")
    parser.add_argument("--ollama-base-url", default=None, help="Override OLLAMA_BASE_URL for this run")
    parser.add_argument("--temperature", type=float, default=None, help="Override IOC_LLM_TEMPERATURE for this run")
    parser.add_argument("--llm-budget", type=int, default=2, help="Maximum semantic LLM calls for this run")
    parser.add_argument("--llm-continue", action="store_true", help="Allow the LLM to decide continue/stop in later phases")
    parser.add_argument("--llm-final-summary", action="store_true", help="Use the LLM to generate the final executive summary")
    parser.add_argument("--trace-dir", default="traces", help="Directory where the execution trace JSON will be written")
    parser.add_argument("--no-trace", action="store_true", help="Disable writing the execution trace JSON")
    return parser.parse_args()


def apply_runtime_llm_overrides(args: argparse.Namespace) -> None:
    """Apply CLI overrides to the current process environment."""
    if args.llm_provider is not None:
        if args.llm_provider == "none":
            os.environ["IOC_ENABLE_LLM"] = "0"
        else:
            os.environ["IOC_ENABLE_LLM"] = "1"
            os.environ["IOC_LLM_PROVIDER"] = args.llm_provider

    if args.llm_model is not None:
        os.environ["IOC_LLM_MODEL"] = args.llm_model

    if args.ollama_base_url is not None:
        os.environ["OLLAMA_BASE_URL"] = args.ollama_base_url

    if args.temperature is not None:
        os.environ["IOC_LLM_TEMPERATURE"] = str(args.temperature)


def build_initial_state(args: argparse.Namespace, seed: str, seed_type: str) -> dict[str, Any]:
    """Build the initial LangGraph state.

    Some LLM fields are duplicated intentionally because older modules may use
    either the operational names or shorter legacy names.
    """
    return {
        "seed_value": seed,
        "seed_type": seed_type,
        "pending_pivots": [],
        "processed_pivots": [],
        "used_pivot_groups": [],
        "last_selected_pivot": None,
        "last_enrichment_result": None,
        "merged_state": None,
        "investigation_phase": "seed_characterization",
        "execution_trace": [],
        "semantic_selection": None,
        "pivot_history": [],
        "stagnation_count": 0,
        "dead_end_count": 0,
        "iteration": 0,
        "max_iterations": args.max_iterations,
        "stop_reason": "",
        "llm_operational_calls_used": 0,
        "llm_operational_budget": args.llm_budget,
        "llm_final_summary_enabled": args.llm_final_summary,
        "llm_final_summary_used": False,
        "llm_calls_used": 0,
        "llm_call_budget": args.llm_budget,
        "enable_llm_continue": args.llm_continue,
        "enable_llm_final_summary": args.llm_final_summary,
        "llm_trace": [],
        "llm_call_trace": [],
        "final_report": "",
    }


def run_workflow_with_optional_progress(app, initial_state: dict[str, Any], args: argparse.Namespace, console, rich_parts):
    _, _, Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn = rich_parts

    if Progress and console:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Running LangGraph workflow", total=3)
            progress.advance(task)
            result = app.invoke(initial_state)
            progress.advance(task)
            trace_path = None if args.no_trace else write_execution_trace(result, output_dir=args.trace_dir)
            progress.advance(task)
            return result, trace_path

    result = app.invoke(initial_state)
    trace_path = None if args.no_trace else write_execution_trace(result, output_dir=args.trace_dir)
    return result, trace_path


def main() -> None:
    load_dotenv()
    args = parse_args()
    apply_runtime_llm_overrides(args)

    rich_parts = _load_console()
    Console, Panel, *_ = rich_parts
    console = Console() if Console else None

    seed = args.seed.strip()
    seed_type = detect_type(seed)

    _print_cli_header(console, Panel, seed, seed_type, args)

    app = build_investigation_workflow()
    initial_state = build_initial_state(args, seed, seed_type)

    result, trace_path = run_workflow_with_optional_progress(
        app=app,
        initial_state=initial_state,
        args=args,
        console=console,
        rich_parts=rich_parts,
    )

    _print_cli_footer(
        console=console,
        Panel=Panel,
        trace_path=trace_path,
        final_report=result.get("final_report", ""),
    )


if __name__ == "__main__":
    main()
