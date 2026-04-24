"""Shared LangGraph state for the investigation workflow.

The workflow tracks both deterministic execution state and semantic-decision
state. The semantic layer is intentionally small: it should help the workflow
choose better pivots and better stopping points without taking control of the
entire pipeline.
"""

from typing import TypedDict, Optional, List, Dict, Any

from models import InvestigationState


class InvestigationGraphState(TypedDict):
    # User-supplied seed.
    seed_value: str
    seed_type: str

    # Iteration counters.
    iteration: int
    max_iterations: int

    # Candidate/selection tracking.
    pending_pivots: List[Dict[str, Any]]
    processed_pivots: List[str]
    used_pivot_groups: List[str]
    last_selected_pivot: Optional[Dict[str, Any]]
    last_enrichment_result: Optional[Dict[str, Any]]

    # Investigation state shared across nodes.
    merged_state: Optional[InvestigationState]

    # Investigation control.
    investigation_phase: str
    execution_trace: List[Dict[str, Any]]
    llm_trace: List[Dict[str, Any]]
    semantic_selection: Optional[Dict[str, Any]]
    pivot_history: List[Dict[str, Any]]
    stagnation_count: int
    dead_end_count: int
    stop_reason: str

    # LLM runtime control.
    llm_operational_calls_used: int
    llm_operational_budget: int
    llm_final_summary_enabled: bool
    llm_final_summary_used: bool

    # Backward-compatible aggregate fields retained for logging/reporting.
    llm_calls_used: int
    llm_call_budget: int
    enable_llm_continue: bool
    enable_llm_final_summary: bool

    # Final human-readable report.
    final_report: str
