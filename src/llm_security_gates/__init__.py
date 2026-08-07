"""llm-security-gates: practical, FOSS-backed security gates for LLM systems.

Three independent gates:
    modelscan_gate  -- block unsafe model files before load (supply chain)
    llmguard_scan   -- scan text with a configurable llm-guard scanner set
    llmguard_proxy  -- OpenAI-compatible reverse proxy that enforces the above
    garak_harness   -- turn a garak run into a per-model resilience score

The decision logic in each module is importable without the heavy ML
dependencies, which are pulled in lazily only when a gate actually runs.
"""

__version__ = "0.1.0"
