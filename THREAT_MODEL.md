# Threat model

The gates process attacker-controlled model files, prompts, scanner output and upstream model responses. Primary risks include unsafe deserialization in optional backends, fail-open parsing or timeout behavior, prompt or secret leakage to an upstream service, denial of service, malicious URLs and treating an incomplete scan as a pass.

The wrappers use explicit verdict contracts and fail closed on unavailable or malformed backend results. Tests use synthetic inputs and do not require downloading models. Operators must pin and isolate optional scanning backends, bound input and execution resources, protect upstream credentials, avoid confidential prompts in logs and authorize every assessed system.

A PASS applies only to the configured gate and evidence observed. It does not prove that a model, artifact or deployment is secure.
