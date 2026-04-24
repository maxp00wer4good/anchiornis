# Anchiornis

**Graph-based CTI investigation with LangGraph, LangChain tools, optional semantic LLMs, and explainable rule inference.**
<p align="left">
  <img src="assets/Anchiornis.png" alt="Anchiornis logo" width="560">
</p>

<p align="left">
  <em>Graph-based CTI investigation with optional semantic LLMs and explainable rule inference.</em>
</p>
Anchiornis investigates a suspicious observable — URL, domain, IP, or hash — by building a graph of observables and relations, expanding only high-value pivots, applying inference rules, and exporting a full technical JSON trace that explains what happened and why.

It is not just a connector runner.

Anchiornis is designed to **correlate**, **reason over relationships**, **prioritize pivots**, **reinforce detections with inference rules**, and optionally use LLMs only where semantic judgment adds value.

```text
      _                _     _                 _     
     / \   _ __   ___ | |__ (_) ___  _ __ _ __ (_)___ 
    / _ \ | '_ \ / __|| '_ \| |/ _ \| '__| '_ \| / __|
   / ___ \| | | | (__ | | | | | (_) | |  | | | | \__ \
  /_/   \_\_| |_|\___||_| |_|_|\___/|_|  |_| |_|_|___/

                     A N C H I O R N I S
                         v.0.2
                    ── Threat Intel ──
```



## Quick start

Install dependencies:

```bash
pip install -r requirements.txt
```

Copy the environment template:

```bash
cp .env.example .env
```

Run a deterministic local investigation without LLMs:

```bash
python anchiornis.py --seed http://youtubeaccount.com --llm-provider none
```

Run with local Ollama:

```bash
python anchiornis.py \
  --seed http://youtubeaccount.com \
  --llm-provider ollama \
  --llm-model llama3.1:8b \
  --ollama-base-url http://host.docker.internal:11434
```

Run with Anthropic and an analyst-style final summary:

```bash
python anchiornis.py \
  --seed http://youtubeaccount.com \
  --llm-provider anthropic \
  --llm-model claude-sonnet-4-6 \
  --llm-budget 2 \
  --llm-final-summary
```

Write traces to a custom directory:

```bash
python anchiornis.py --seed http://example.com --trace-dir runs
```

Disable trace writing:

```bash
python anchiornis.py --seed http://example.com --no-trace
```

Show version:

```bash
python anchiornis.py --version
```

---

## CLI manual

Main executable:

```bash
python anchiornis.py [OPTIONS]
```

Basic form:

```bash
python anchiornis.py --seed <observable> [options]
```

### Options

| Option | Type / values | Default | Description |
|---|---|---:|---|
| `--seed` | string | `http://youtubeaccount.com` | Seed observable to investigate. Can be a URL, domain, IP, or hash. |
| `--max-iterations` | integer | `12` | Safety limit for LangGraph workflow iterations. Prevents uncontrolled pivot expansion. |
| `--llm-provider` | `none`, `ollama`, `anthropic` | env/default | Selects the semantic LLM backend for this run. Use `none` for fully deterministic execution. |
| `--llm-model` | string | env/default | Overrides `IOC_LLM_MODEL` for this run. Example: `llama3.1:8b` or `claude-sonnet-4-6`. |
| `--ollama-base-url` | URL | env/default | Overrides `OLLAMA_BASE_URL` for this run. Only applies when `--llm-provider ollama` is used. |
| `--temperature` | float | env/default | Overrides `IOC_LLM_TEMPERATURE`. Recommended value for repeatable CTI work is `0.0`. |
| `--llm-budget` | integer | `2` | Maximum number of operational semantic LLM calls for investigative decisions. |
| `--llm-continue` | flag | disabled | Allows the LLM to participate in late-phase continue/stop decisions. If omitted, stop logic remains deterministic. |
| `--llm-final-summary` | flag | disabled | Uses the LLM to generate the final analyst-style closing note. |
| `--trace-dir` | path | `traces` | Directory where the JSON execution trace will be written. |
| `--no-trace` | flag | disabled | Disables writing the JSON execution trace. |
| `--version` | flag | — | Prints the Anchiornis version and exits. |

### LLM-related options

These options control semantic LLM behavior:

```text
--llm-provider
--llm-model
--ollama-base-url
--temperature
--llm-budget
--llm-continue
--llm-final-summary
```

Use no LLM:

```bash
python anchiornis.py --seed http://example.com --llm-provider none
```

Use local Ollama:

```bash
python anchiornis.py \
  --seed http://example.com \
  --llm-provider ollama \
  --llm-model llama3.1:8b \
  --ollama-base-url http://localhost:11434
```

Use Anthropic for semantic decisions and final summary:

```bash
python anchiornis.py \
  --seed http://example.com \
  --llm-provider anthropic \
  --llm-model claude-sonnet-4-6 \
  --llm-budget 2 \
  --llm-final-summary
```

### Trace-related options

These options control JSON trace output:

```text
--trace-dir
--no-trace
```

Write traces to the default directory:

```bash
python anchiornis.py --seed http://example.com
```

Write traces to another directory:

```bash
python anchiornis.py --seed http://example.com --trace-dir runs
```

Disable trace output:

```bash
python anchiornis.py --seed http://example.com --no-trace
```

### Recommended commands

Fully deterministic mode:

```bash
python anchiornis.py \
  --seed http://youtubeaccount.com \
  --llm-provider none
```

Local semantic mode with Ollama:

```bash
python anchiornis.py \
  --seed http://youtubeaccount.com \
  --llm-provider ollama \
  --llm-model llama3.1:8b \
  --llm-budget 2
```

Cloud semantic mode with final analyst note:

```bash
python anchiornis.py \
  --seed http://youtubeaccount.com \
  --llm-provider anthropic \
  --llm-model claude-sonnet-4-6 \
  --llm-budget 2 \
  --llm-final-summary
```

Automation-friendly deterministic run with custom trace directory:

```bash
python anchiornis.py \
  --seed http://youtubeaccount.com \
  --llm-provider none \
  --trace-dir runs
```

---

## What Anchiornis does

Anchiornis takes a suspicious seed observable and tries to answer practical CTI questions:

- What is the suspicious entrypoint?
- What relations and infrastructure surround it?
- Which pivots are worth expanding?
- Which branches are noisy or low value?
- Which signals are direct observations and which are derived by inference rules?
- What did the LLM decide, if an LLM was used?
- Why did the workflow stop?
- What evidence supports the final assessment?

The output is intentionally split:

- the **terminal output** stays compact and readable;
- the **JSON trace** stores the full technical reasoning trail.

---

## Why Anchiornis is different

Many IOC tools behave like connector runners: query VirusTotal, query urlscan, query AbuseIPDB, print results.

Anchiornis is designed differently.

It treats the investigation as a graph problem:

```text
observables -> relations -> inference -> pivots -> expansion -> final assessment
```

The important part is not just collecting facts, but understanding how facts relate to each other.

Anchiornis:

- builds a normalized graph of observables and relations;
- separates direct evidence from derived findings;
- scores pivots structurally before expanding them;
- avoids blindly following noisy web context;
- keeps the suspicious seed as the center of the case;
- uses a YAML-based inference engine to reinforce detection;
- can use LLMs for semantic decisions without handing them the whole investigation;
- exports a JSON trace that makes the logic auditable.

---

## Technology approach

Anchiornis combines deterministic CTI engineering with modern agentic infrastructure.

### LangGraph as the workflow backbone

The investigation is modeled as a LangGraph state machine.

```text
START
  -> seed_intake
  -> initial_enrichment
  -> correlate
  -> extract_pivots
  -> select_next_pivot
  -> enrich_pivot
  -> stop_or_continue
      -> correlate
      -> final_report
  -> END
```

LangGraph provides a clear execution model: each node has a role, the state is explicit, and stop/continue behavior is controlled.

### LangChain tools as the integration layer

Anchiornis can expose investigation functions as LangChain tools.

This allows the workflow to be used from agentic contexts without turning the whole system into an uncontrolled autonomous agent.

The current design favors **coarse, safe tools** over dozens of tiny tools that could cause uncontrolled expansion.

### Optional LLMs

LLMs are optional.

Supported semantic backends:

```text
none
ollama
anthropic
```

Anchiornis can run fully without LLMs:

```bash
python anchiornis.py --seed http://youtubeaccount.com --llm-provider none
```

When LLMs are enabled, they are used only for tasks where semantic judgment is useful:

- choosing between a small set of good pivot candidates;
- optionally deciding whether late-phase work is still useful;
- producing the final analyst-style closing note.

The LLM does **not** own collection, normalization, graph construction, rule inference, or stop conditions.

---

## Cloud LLM economy

Anchiornis is designed to be careful with cloud LLM usage.

The system does not send the full raw graph to the model. Instead, it builds small decision views containing only the information needed for the decision.

The operational LLM budget is controlled with:

```bash
--llm-budget
```

Example:

```bash
python anchiornis.py \
  --seed http://youtubeaccount.com \
  --llm-provider anthropic \
  --llm-model claude-sonnet-4-6 \
  --llm-budget 2
```

This means Anchiornis can use advanced semantic reasoning without turning every connector response into an expensive prompt.

The final analyst summary can be enabled separately:

```bash
--llm-final-summary
```

This makes the economics explicit:

- deterministic code handles most of the workflow;
- the LLM is used sparingly;
- local Ollama is supported;
- full no-LLM fallback is supported;
- every LLM call can be written to the JSON trace.

---

## Environment configuration

Connector keys:

```env
VT_API_KEY=...
ABUSEIPDB_API_KEY=...
URLSCAN_API_KEY=...
```

Disable LLMs:

```env
IOC_ENABLE_LLM=0
```

Use Ollama:

```env
IOC_ENABLE_LLM=1
IOC_LLM_PROVIDER=ollama
IOC_LLM_MODEL=llama3.1:8b
OLLAMA_BASE_URL=http://host.docker.internal:11434
IOC_LLM_TEMPERATURE=0.0
```

Use Anthropic:

```env
IOC_ENABLE_LLM=1
IOC_LLM_PROVIDER=anthropic
IOC_LLM_MODEL=claude-sonnet-4-6
ANTHROPIC_API_KEY=your_api_key_here
IOC_LLM_TEMPERATURE=0.0
```

Notes:

- `OLLAMA_BASE_URL` only applies to Ollama.
- `ANTHROPIC_API_KEY` only applies to Anthropic.
- If `IOC_ENABLE_LLM=0`, Anchiornis remains usable with deterministic selection only.

---

## JSON trace output

Every CLI execution writes a technical JSON trace by default.

Default directory:

```text
traces/
```

Filename format:

```text
ioc_trace_YYYYMMDDTHHMMSSZ_<seed>.json
```

The JSON trace is one of the most important parts of Anchiornis. It is designed to explain the investigation logic, not just store raw connector output.

A clean trace should contain:

```json
{
  "schema_version": "0.2",
  "tool": {
    "name": "Anchiornis",
    "version": "0.2"
  },
  "run": {
    "id": "...",
    "started_at": "...",
    "finished_at": "...",
    "duration_ms": 0
  },
  "input": {
    "seed": {
      "type": "url",
      "value": "http://youtubeaccount.com"
    }
  },
  "config": {},
  "summary": {},
  "knowledge_graph": {
    "observables": [],
    "relations": [],
    "evidence": []
  },
  "inference": {
    "engine": "yaml_dsl_poc",
    "rules_loaded": [],
    "rules_fired": [],
    "derived_relations": []
  },
  "pivoting": {
    "history": [],
    "expansions": [],
    "pending_at_stop": []
  },
  "llm": {
    "operational_calls_used": 0,
    "operational_budget": 0,
    "calls": []
  },
  "timeline": []
}
```

### Trace design

The trace separates lightweight summaries from heavy evidence.

- `summary` gives the high-level outcome.
- `knowledge_graph` contains the final graph.
- `inference` lists rule-derived findings.
- `pivoting.history` stores lightweight pivot summaries.
- `pivoting.expansions` stores detailed pivot expansion deltas.
- `llm.calls` stores prompts and model responses when LLMs are used.
- `timeline` stores readable operational events.

The goal is to avoid duplicating large relation lists in multiple places.

---

## Inference engine

Anchiornis includes a rule inference engine that reinforces detection by turning low-level observed relations into explicit derived findings.

The engine lives under:

```text
engine/inference.py
engine/inference_runner.py
engine/rules/v1/*.yaml
```

It works over the normalized investigation graph:

1. Connectors collect facts from sources such as VirusTotal, urlscan, and AbuseIPDB.
2. Those facts are normalized into direct relations.
3. YAML rules are loaded dynamically.
4. The inference engine matches rules against the relation graph.
5. Matching rules emit new derived relations.
6. Derived relations preserve explainability metadata such as rule ID and input relation IDs.
7. Pivot extraction can give structural bonuses to relations reused by derived findings.

This means the inference engine is not cosmetic. It reinforces detection in three ways:

- it compresses several low-level observations into clearer signals;
- it makes the trace explainable because every derived finding points back to inputs;
- it can influence pivot prioritization when direct relations participate in derived findings.

### Current status: PoC / v1

The inference engine is currently a proof of concept with three YAML rules:

```text
multi_engine.yaml       Multi-engine malicious consensus
domain_parking.yaml     Domain parking behavior
cert_divergence.yaml    Certificate or final-domain divergence
```

The value of this PoC is not that it already contains a large CTI rule library.

The value is that the architecture works:

- YAML-based DSL format;
- dynamic rule loading;
- graph relation matching;
- evidence propagation;
- derived-relation output model;
- integration into pivot scoring and final trace.

Adding more rules should not require rewriting the workflow.

---

## Direct vs derived relations

Anchiornis separates two kinds of relationships.

### Direct relations

Direct relations come from normalized connector evidence.

Examples:

```text
url -> final_domain -> domain
domain -> resolves_to -> ip
url -> observed_domain -> domain
hash -> detected_by -> engine
```

### Derived relations

Derived relations come from the inference engine.

Examples:

```text
url -> has_consensus_signal -> signal:multi_engine_malicious
url -> shows_parking_behavior -> signal:domain_parking
domain -> has_certificate_divergence -> signal:certificate_mismatch
```

A derived relation should always remain explainable through metadata such as:

```json
{
  "source": "rules_engine",
  "relation_tier": "derived",
  "rule_id": "RULE_DOMAIN_PARKING",
  "input_relations": ["rel_001", "rel_002", "rel_003"]
}
```

---

## Pivoting methodology

Anchiornis does not expand every observable.

It extracts and scores pivot candidates, then expands only the most useful ones.

The pivoting methodology has three stages:

1. extract candidates from high-signal graph relations;
2. rank candidates structurally;
3. optionally use an LLM to choose among a small curated candidate set.

The structural pivot score is not a threat score. It is a prioritization score.

A pivot can be selected because it is central to the case, even if the final maliciousness assessment is still unknown.

---

## Investigation phases

Anchiornis works in phases instead of treating every pivot equally.

### 1. Seed characterization

Goal:

- understand the suspicious entrypoint;
- identify the landing chain;
- detect strong negative signals;
- find central infrastructure;
- avoid getting lost in isolated artifacts too early.

Typical high-value pivots:

```text
final_domain
final_url
resolves_to
central infrastructure
```

### 2. Lateral correlation

Goal:

- look sideways, not just deeper;
- identify repeated infrastructure;
- find rare observed domains or supporting artifacts;
- avoid expanding noisy destination context.

Typical pivots:

```text
rare observed domains
infrastructure-level pivots
repeated auxiliary families
```

### 3. Closure

Goal:

- stop when marginal value drops;
- summarize what mattered;
- distinguish strong findings from weaker branches.

---

## Avoiding noisy destination context

A common IOC-analysis failure mode is treating the final landing page as the malicious core simply because it appears at the end of a redirect chain.

Anchiornis avoids that.

The workflow uses structural signals to detect when a final destination looks like high-fanout web context rather than the core suspicious asset.

When that happens:

- the final destination is not automatically promoted as the main pivot;
- ordinary third-party dependencies are not automatically expanded;
- lateral correlation remains focused on the suspicious seed chain.

This is implemented structurally, not with hardcoded brand allowlists or blocklists.

---

## Usefulness metric

Anchiornis tracks an internal metric called `usefulness` after each pivot expansion.

It measures how much the expansion improved the case.

It is derived from:

- new relations;
- new observables;
- new evidence.

Important:

`usefulness` is not a final analyst-facing risk score.

It is useful for workflow debugging and pivot analysis, but the final report should translate it into human language, such as:

```text
productive pivot
useful supporting context
limited additional value
dead end
```

---

## Stop algorithm

Anchiornis stops deterministically by default.

Stop reasons can include:

- no viable high-value pivots remain;
- too many dead ends in a row;
- stagnation;
- max iteration safety limit.

In lateral correlation, the workflow is intentionally stricter. It should stop instead of continuing just because weak nodes still exist in the raw graph.

---

## Final analyst summary

By default, Anchiornis prints a compact deterministic closing summary.

When enabled with:

```bash
--llm-final-summary
```

the final output becomes an analyst-style closing note.

The final summary should explain:

- what the suspicious entrypoint was;
- what the strongest signals were;
- which pivots mattered most;
- what lateral structure was found;
- which branches were lower value;
- what the final analytic judgment is.

It should not simply dump raw pivot history or internal metrics.

---

## Important files

```text
anchiornis.py           CLI entrypoint, version banner, runtime provider selection, Rich UI
graph/workflow.py      LangGraph wiring
graph/nodes.py         Workflow nodes, phase logic, stop logic, report generation
core/pivots.py         Deterministic structural pivot extraction
core/semantic_llm.py   LLM provider abstraction, candidate views, final narrative summary
core/expansion.py      Pivot expansion and merge logic
core/investigator.py   Connector orchestration and inference execution
core/trace.py          JSON trace export
engine/inference.py    YAML rule matching engine
engine/rules/v1/*.yaml Rule definitions
connectors/*           API clients and normalization
```

---

## Design principles

Anchiornis follows these rules:

- The seed remains the center of the case.
- Threat entrypoint and final destination are not automatically the same thing.
- No hardcoded brand allowlists or blocklists drive the core decisions.
- The raw graph is preserved.
- Decisions use compact graph views.
- Pivot candidates must be small and high-signal.
- Lateral correlation only uses relevant artifacts.
- LLMs are optional and budgeted.
- Local Ollama and no-LLM fallback are first-class modes.
- JSON trace output must explain the logic.

---

## Practical interpretation

A one-line summary of the methodology:

> First understand the suspicious seed, then separate useful case structure from noisy web context, perform lateral correlation only on relevant artifacts, reinforce detections with explainable inference rules, and finally translate the findings into grounded analyst language.

---

## Roadmap / TODO

Anchiornis v0.2 is a working CTI investigation PoC. The next steps are focused on persistence, richer inference, stronger scoring, more connectors, and better analyst workflows.

### Persistence and data model

- Add a database layer for executions, observables, relations, evidence, pivots, and assessments.
- Consider Neo4j or ArangoDB for graph-heavy investigation queries.
- Alternatively, start with PostgreSQL plus JSONB for evidence and run metadata.
- Add run comparison for repeated investigations of the same IOC.
- Add cross-run deduplication to detect recurring infrastructure historically.

### Inference engine

- Expand the YAML rule library beyond the current three-rule PoC.
- Add rules for redirect chains, shared infrastructure, certificate reuse, ASN clustering, suspicious hosting patterns, domain age, repeated URL paths, and hash-to-URL reuse.
- Add severity and confidence fields to rules.
- Add categories such as reputation, infrastructure, redirect, certificate, malware, phishing, and campaign clustering.
- Add positive and negative fixtures for each YAML rule.
- Add rule metadata: author, created date, updated date, ATT&CK mapping, confidence rationale, and false-positive notes.
- Add safe multi-hop inference where derived relations can trigger second-order rules.

### CTI risk scoring

- Add a CTI-style risk score separate from structural pivot score.
- Score final results using severity, confidence, evidence diversity, source reliability, recency, infrastructure centrality, and corroboration.
- Produce final risk levels such as low, medium, high, or critical.
- Keep separate scores for:
  - maliciousness of the seed;
  - infrastructure risk;
  - pivot value;
  - attribution or campaign-clustering confidence;
  - false-positive likelihood.
- Include human-readable rationale for every score.
- Export risk scoring details in the JSON trace.

### MITRE ATT&CK and CTI mapping

- Map derived relations and rule hits to MITRE ATT&CK techniques where appropriate.
- Add support for CTI concepts such as tactic, technique, procedure, campaign, malware family, intrusion set, infrastructure, indicator, and observed data.
- Consider STIX 2.1 export for observables, indicators, relationships, reports, and observed-data objects.
- Add rule-level mappings to MITRE ATT&CK, CAPEC, CWE, or Malware Behavior Catalog where relevant.
- Include mappings in the final JSON trace and analyst summary.

### More connectors

- Add connectors for Shodan, Censys, GreyNoise, OTX, MISP, URLhaus, PhishTank, OpenPhish, Spamhaus, ThreatFox, MalwareBazaar, Hybrid Analysis, and certificate transparency sources.
- Add passive DNS and WHOIS/RDAP enrichment.
- Add support for local enrichment files such as internal blocklists, known-good assets, customer allowlists, and historical incident data.
- Add connector-level reliability metadata.
- Add caching and rate-limit handling per connector.

### CLI and analyst experience

- Improve the Rich CLI with clearer phase panels, colored progress bars, and compact summaries.
- Add `--json-only` for automation pipelines.
- Add `--output` and `--case-id` controls.
- Add table views for direct relations, derived findings, selected pivots, and risk scoring.
- Add Markdown or HTML analyst report export.

### Evaluation and quality

- Add synthetic test cases for benign, suspicious, and malicious IOCs.
- Add regression tests for pivot selection and stop conditions.
- Add golden trace files to detect accidental behavior changes.
- Track metrics such as useful pivots, dead-end rate, derived findings, evidence diversity, and final risk score stability.
- Add false-positive review notes for noisy rule families.

### Architecture and operations

- Separate library code from CLI code more strictly.
- Add service/API mode for external systems.
- Add Docker packaging and example compose files.
- Add structured logging and optional OpenTelemetry spans.
- Add secrets validation and safer missing-key handling.
- Add async connector execution where APIs allow it.

### Agentic layer

- Keep LangGraph as the deterministic backbone.
- Add granular LangChain tools only when they provide real value, such as:
  - `enrich_domain`
  - `enrich_ip`
  - `query_urlscan`
  - `query_vt`
  - `run_inference`
  - `export_trace`
- Avoid turning every internal function into a tool.
- Add guardrails so agents cannot over-expand pivots or ignore deterministic stop conditions.

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE).

## About the project

Anchiornis is a personal research project developed by Jesus Friginal, focused on practical, explainable, and graph-driven Cyber Threat Intelligence.

The goal is not to build another connector runner, but a modest and honest contribution to better threat hunting workflows: reducing noise, prioritizing what matters, and helping analysts reason over relationships instead of isolated indicators.

The name Anchiornis is intentional.

Anchiornis was one of the earliest feathered dinosaurs discovered — a small transitional creature between classic dinosaurs and modern birds. It was not the largest predator, nor the strongest hunter, but it represents evolution, transition, and the beginning of a new way of understanding complex systems.

That idea fits this project.

Threat hunting often works the same way: not by brute force, but by patiently following traces, observing weak signals, and understanding how small relationships reveal larger structures.

Anchiornis tries to do exactly that.

It is not a giant platform, nor a finished product, but a small evolutionary step toward more explainable, practical, and analyst-centered CTI workflows.


## Contact

For questions, collaboration, research discussions, or CTI-related conversations:

Jesus Friginal - maxp00wer.4good@gmail.com
