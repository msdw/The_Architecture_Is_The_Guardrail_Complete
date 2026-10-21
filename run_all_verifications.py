"""Master Companion Verification Runner for:
THE ARCHITECTURE IS THE GUARDRAIL: Engineering Reliable and Secure AI Agents Beyond the Prompt

Requires the Book Reader Access Key defined in the Front Matter and Appendix A:
    --access-key GUARDRAIL-RING0-2026-SHA256
or environment variable:
    GUARDRAIL_ACCESS_KEY=GUARDRAIL-RING0-2026-SHA256
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
import subprocess
import sys
from pathlib import Path

EXPECTED_ACCESS_KEY_SHA256 = (
    "e8879c132bb9eb24875fd1e7b9a3f5c280075a68a5355125bf490d8e4d662940"
)

VERIFICATION_MODULES = [
    ("Chapter 1 — Trajectory Math & Compaction Dilution", "verify_ch01_calcs.py"),
    ("Chapter 1 — DeterministicActionGateway Reference", "ch01_gateway_demo.py"),
    ("Chapter 2 — Latency, Quadratic Tokens & ECST Math", "verify_ch02_calcs.py"),
    ("Chapter 2 — Bounded State Machine (Level 2) Demo", "ch02_agency_spectrum_demo.py"),
    ("Chapter 3 — Out-of-Band Metadata & 5-State Envelopes", "ch03_tool_contracts_demo.py"),
    ("Chapter 4 — Pre-Prompt RAG ACLs & Rule of Two Taint", "ch04_taint_tracking_demo.py"),
    ("Chapter 5 — Deterministic SHA-256 Idempotency Ledger", "ch05_idempotency_checkpoints_demo.py"),
    ("Chapters 6–10 — M/M/1 Queue, Rogan-Gladen & Hash Chain", "verify_ch06_7_8_9_10_calcs.py"),
    ("Chapters 3–10 — Expanded Mechanisms & Statistical Proofs", "verify_expanded_calcs_and_code.py"),
    ("Empirical Benchmark Labs — Labs 1.1, 5.1 & 6.1 (10k Monte Carlo & DES)", "run_empirical_benchmark_labs.py"),
    ("Appendix D — Unified 4-Ring Agent Harness Integration", "appendix_d_unified_harness_demo.py"),
]


def verify_access_key(provided_key: str) -> bool:
    digest = hashlib.sha256(provided_key.strip().encode("utf-8")).hexdigest()
    return digest == EXPECTED_ACCESS_KEY_SHA256


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Execute all deterministic math & code verification suites from the book."
    )
    parser.add_argument(
        "--access-key",
        default=os.environ.get("GUARDRAIL_ACCESS_KEY", ""),
        help="Reader Access Key printed in the book Front Matter & Appendix A.",
    )
    args = parser.parse_args()

    if not args.access_key or not verify_access_key(args.access_key):
        print("======================================================================", file=sys.stderr)
        print(" [ACCESS DENIED] Invalid or missing Book Reader Access Key.", file=sys.stderr)
        print(" Please provide the access key printed in the Front Matter ('Companion", file=sys.stderr)
        print(" Code Repository & Reader Access Key') or Appendix A of the book:", file=sys.stderr)
        print("   python -I run_all_verifications.py --access-key <BOOK_ACCESS_KEY>", file=sys.stderr)
        print("======================================================================", file=sys.stderr)
        return 1

    base_dir = Path(__file__).resolve().parent
    print("======================================================================")
    print(" [ACCESS GRANTED] Reader Access Key Verified (SHA-256 Match)")
    print(" Book: THE ARCHITECTURE IS THE GUARDRAIL (First Edition, 2026)")
    print("======================================================================\n")

    passed = 0
    for label, filename in VERIFICATION_MODULES:
        script_path = base_dir / filename
        print(f"---> Running [{label}] ({filename}) ...")
        proc = subprocess.run(
            [sys.executable, "-I", str(script_path)],
            cwd=str(base_dir),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            print(f"[FAILED] {filename} exited with code {proc.returncode}", file=sys.stderr)
            print(proc.stdout)
            print(proc.stderr, file=sys.stderr)
            return proc.returncode
        passed += 1
        print(f"     [OK] {filename} verified.")

    claims_path = base_dir / "claims.csv"
    if claims_path.exists():
        with claims_path.open("r", encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        verified_count = sum(1 for r in rows if r.get("status") == "VERIFIED")
        print(f"\n---> Checked claims.csv ledger: {verified_count}/{len(rows)} claims VERIFIED.")

    print("\n======================================================================")
    print(f" ALL {passed}/{len(VERIFICATION_MODULES)} SUITE MODULES PASSED DETERMINISTIC VERIFICATION.")
    print("======================================================================")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
