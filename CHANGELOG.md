# Changelog

## v.0.2 - 2026-04-24

- Added explicit investigation phases (`seed_characterization`, `lateral_correlation`, `closure`) to the LangGraph state.
- Reworked pivot selection so early seed characterization can stay deterministic and later semantic calls are budgeted.
- Reworked candidate payload construction to prefer better candidates instead of simply showing more candidates.
- Added family, role, phase, usefulness and LLM rationale to pivot history records.
- Switched graph logs to a more readable English workflow style.
- Reduced semantic LLM verbosity by removing response previews and prompt-length spam.
- Grounded the final semantic summary on explicit supported findings instead of broad raw context.
- Updated README with explicit Anthropic `.env` configuration and new playground flags.

### Added
- `llm_call_budget`, `enable_llm_continue` and `enable_llm_final_summary` runtime controls.
- Compact phase-aware decision views for LLM selection.
- Support for source-provided seen times in semantic snapshots.

### Notes
- The workflow now keeps the full graph but uses compact views for decisions instead of feeding raw graph context to the LLM.
- No synthetic system timestamps are used in the semantic layer.

### Refined
- Final LLM summary now replaces the raw end-of-run dump when `--llm-final-summary` is enabled.
- The final closing note is now built from structured case context instead of raw pivot history alone.
- Added concrete lateral family rollups and observable-type breakdowns for the analyst closing note.
- Added generic structural handling for high-fanout benign/commercial destination context so sink dependencies do not dominate later pivots.
- Improved deterministic stop logic so weak sink-derived branches and isolated low-value lateral IPs can terminate the workflow earlier.
- Extended the README with a full methodology section covering nodes, scoring, `usefulness`, stop logic, and final-summary behavior.
