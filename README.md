# The Architecture Is the Guardrail — Companion Code & Verification Vault

**Monograph:** *The Architecture Is the Guardrail: Engineering Reliable and Secure AI Agents Beyond the Prompt* (First Edition, 2026)  
**Runtime Standard:** Python 3.12+ (100% Zero-Dependency Standard Library Implementations)  
**Repository Status:** Closed Reader Companion Vault (`msdw/The_Architecture_Is_The_Guardrail_Complete`)

---

## 1. Reader Access Key & Suite Unlocking

This private companion repository contains the complete suite of executable reference implementations, deterministic mathematical models, queueing simulators, statistical calibration pipelines, seeded chaos engineering injectors, and the 48-claim verification ledger (`claims.csv`) referenced across Chapters 1 through 10 and Appendices A–D of the book.

To unlock and execute the full verification suite, supply the **Book Reader Access Key** printed in the Front Matter (*Companion Code Repository & Reader Access Key*) and Appendix A of your copy of the book:

```bash
python -I run_all_verifications.py --access-key <BOOK_READER_ACCESS_KEY>
```

Or via environment variable:

```bash
export GUARDRAIL_ACCESS_KEY="<BOOK_READER_ACCESS_KEY>"
python -I run_all_verifications.py
```

*(Note: `run_all_verifications.py` validates the SHA-256 digest `e8879c132bb9eb24875fd1e7b9a3f5c280075a68a5355125bf490d8e4d662940` of the book access key before running all 10 verification modules.)*

---

## 2. Repository Structure & Chapter Mapping

| File | Book Chapter & Section | Primary Architectural Components & Proofs |
| :--- | :--- | :--- |
| [`run_all_verifications.py`](./run_all_verifications.py) | **Front Matter & App. A** | Password-gated master test runner verifying all 10 suites and `claims.csv`. |
| [`verify_ch01_calcs.py`](./verify_ch01_calcs.py) | **Ch. 1 (Sec. 1.2 & 1.3)** | Context compaction dilution ($25.0\% \to 0.83\%$) and $\text{pass}@5$ ($98.96\%$) vs. $\text{pass}^5$ ($7.69\%$) reliability gap. |
| [`ch01_gateway_demo.py`](./ch01_gateway_demo.py) | **Ch. 1 (Sec. 1.4)** | `DeterministicActionGateway`, `ExecutionSession`, and `ToolProposal` separation. |
| [`verify_ch02_calcs.py`](./verify_ch02_calcs.py) | **Ch. 2 (Sec. 2.3)** | Sequential tail latency, quadratic input token growth $T_{\text{cum\_in}}(N)$, and Effective Cost per Successful Task ($\text{ECST}$). |
| [`ch02_agency_spectrum_demo.py`](./ch02_agency_spectrum_demo.py) | **Ch. 2 (Sec. 2.4)** | `run_bounded_refund_workflow` refactoring an open loop into a deterministic Level 2 State Machine. |
| [`ch03_tool_contracts_demo.py`](./ch03_tool_contracts_demo.py) | **Ch. 3 (Sec. 3.3–3.6)** | `AuthoritativeActionGateway` (out-of-band metadata lookup), 5-State `ToolEnvelope`, and `redirect_stdout` JSON-RPC hygiene. |
| [`ch04_taint_tracking_demo.py`](./ch04_taint_tracking_demo.py) | **Ch. 4 (Sec. 4.3–4.5)** | `retrieve_with_pre_prompt_acl` (pre-ranking RAG ACL filter) and `CapabilityTaintGateway` (*Rule of Two* enforcement). |
| [`ch05_idempotency_checkpoints_demo.py`](./ch05_idempotency_checkpoints_demo.py) | **Ch. 5 (Sec. 5.2–5.3)** | `compute_idempotency_key` and `IdempotentMutationExecutor` (`IN_FLIGHT`, `COMPLETED`, `FAILED_RETRYABLE`). |
| [`verify_ch06_7_8_9_10_calcs.py`](./verify_ch06_7_8_9_10_calcs.py) | **Ch. 6–10 (Core)** | $M/M/1$ human review queue collapse, Rogan-Gladen LLM Judge calibration, Wilson 95% CIs, Rule of Three, and `TamperEvidentAuditLog`. |
| [`verify_expanded_calcs_and_code.py`](./verify_expanded_calcs_and_code.py) | **Ch. 3–10 (Advanced)** | Progressive Tool Disclosure ($-85.4\%$ tokens), MCP SHA-256 schema pinning, `ProvenanceGatedMemoryVault`, `DeterministicSagaCoordinator`, Pollaczek-Khinchine $M/G/1$ variance penalty, $M/M/2$ pooling, McNemar's exact paired test, `argv` shell allowlist verifier, forensic trace replay, Population Stability Index ($\text{PSI}$), and `AgentReleaseBundleManifest`. |
| [`appendix_d_unified_harness_demo.py`](./appendix_d_unified_harness_demo.py) | **Appendix D** | Complete end-to-end 4-Ring `UnifiedAgentHarness` composing taint tracking, out-of-band metadata, idempotency, HMAC human diff tokens, state oracles, and hash-chained redacted logs. |
| [`claims.csv`](./claims.csv) | **All Chapters** | Epistemic verification ledger tracking all 48 quantitative, code, and architectural claims in the monograph. |

---

## 3. Running Individual Chapter Suites

Every script is self-contained and executes in isolated mode (`python -I`) using only the Python 3.12+ standard library:

```bash
python -I verify_ch01_calcs.py
python -I ch01_gateway_demo.py
python -I verify_ch02_calcs.py
python -I ch02_agency_spectrum_demo.py
python -I ch03_tool_contracts_demo.py
python -I ch04_taint_tracking_demo.py
python -I ch05_idempotency_checkpoints_demo.py
python -I verify_ch06_7_8_9_10_calcs.py
python -I verify_expanded_calcs_and_code.py
python -I appendix_d_unified_harness_demo.py
```

---

## 4. Note pour l'Auteur / Propriétaire du Dépôt (`msdw`)

Ce dépôt privé (`https://github.com/msdw/The_Architecture_Is_The_Guardrail_Complete`) constitue le coffre-fort de code compagnon référencé dans le livre (*Front Matter* et *Appendices A & D*).  
La clé d'accès lecteur imprimée dans l'ouvrage est : **`GUARDRAIL-RING0-2026-SHA256`**.
