from __future__ import annotations

"""LangGraph workflow definition.

The graph is intentionally simple:

seed -> enrich -> correlate -> extract pivots -> select pivot -> enrich pivot ->
(decide continue/stop) -> final report

What changed in this version is not the overall shape of the workflow but *who*
performs the semantic decisions. Deterministic Python still handles collection,
merging and deduplication, while an optional local LLM can guide the pivot
selection and the stop decision.
"""

from langgraph.graph import END, START, StateGraph

from graph.nodes import (
    correlate,
    enrich_pivot,
    extract_pivots_node,
    final_report_node,
    initial_enrichment,
    seed_intake,
    select_next_pivot,
    stop_or_continue,
)
from graph.state import InvestigationGraphState


def build_investigation_workflow():
    """Compile and return the investigation graph."""

    graph = StateGraph(InvestigationGraphState)

    graph.add_node("seed_intake", seed_intake)
    graph.add_node("initial_enrichment", initial_enrichment)
    graph.add_node("correlate", correlate)
    graph.add_node("extract_pivots", extract_pivots_node)
    graph.add_node("select_next_pivot", select_next_pivot)
    graph.add_node("enrich_pivot", enrich_pivot)
    graph.add_node("final_report", final_report_node)

    graph.add_edge(START, "seed_intake")
    graph.add_edge("seed_intake", "initial_enrichment")
    graph.add_edge("initial_enrichment", "correlate")
    graph.add_edge("correlate", "extract_pivots")
    graph.add_edge("extract_pivots", "select_next_pivot")
    graph.add_edge("select_next_pivot", "enrich_pivot")

    graph.add_conditional_edges(
        "enrich_pivot",
        stop_or_continue,
        {
            "correlate": "correlate",
            "final_report": "final_report",
        },
    )

    graph.add_edge("final_report", END)

    return graph.compile()
