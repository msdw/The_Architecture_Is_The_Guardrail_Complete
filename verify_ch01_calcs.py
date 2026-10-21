"""Verification script for quantitative examples in BOOK-001, Chapter 1.

Purpose:
Ensure that every numerical claim or worked calculation in Chapter 1 is mathematically
exact, reproducible, and used only where calculation genuinely illuminates an
architectural trade-off:
1. Compound step reliability (pass@1 vs. trajectory reliability p^k and k-step failure probability).
2. Context window growth and instruction dilution across a multi-step tool loop.
"""

from __future__ import annotations


def compound_trajectory_reliability(step_success_prob: float, steps: int) -> dict[str, float]:
    """Calculate probability of completing all `steps` without a single unrecovered failure."""
    all_succeed = step_success_prob ** steps
    at_least_one_failure = 1.0 - all_succeed
    return {
        "step_prob": step_success_prob,
        "steps": steps,
        "trajectory_success": round(all_succeed, 4),
        "failure_rate": round(at_least_one_failure, 4),
    }


def repeated_trial_reliability(trajectory_prob: float, trials: int) -> dict[str, float]:
    """Calculate pass@k (at least one success in k trials) vs pass^k (all k trials succeed)."""
    pass_at_k = 1.0 - ((1.0 - trajectory_prob) ** trials)
    pass_pow_k = trajectory_prob ** trials
    return {
        "single_run_prob": round(trajectory_prob, 4),
        "trials": trials,
        "pass_at_k": round(pass_at_k, 4),
        "pass_pow_k": round(pass_pow_k, 4),
    }


def context_dilution_simulation(
    system_prompt_tokens: int,
    avg_tool_Exchange_tokens: int,
    steps: int,
    compaction_threshold_tokens: int,
) -> dict[str, float | int | bool]:
    """Compute the share of the context window occupied by the initial system instructions."""
    total_uncompacted = system_prompt_tokens + (avg_tool_Exchange_tokens * steps)
    instruction_share_pct = (system_prompt_tokens / total_uncompacted) * 100.0
    compaction_triggered = total_uncompacted > compaction_threshold_tokens
    return {
        "system_prompt_tokens": system_prompt_tokens,
        "steps": steps,
        "total_tokens": total_uncompacted,
        "instruction_share_pct": round(instruction_share_pct, 2),
        "compaction_triggered": compaction_triggered,
    }


if __name__ == "__main__":
    print("=== 1. Trajectory Reliability Across Multi-Step Chains ===")
    for p in (0.95, 0.90, 0.85):
        for n_steps in (1, 5, 10, 15):
            res = compound_trajectory_reliability(p, n_steps)
            print(
                f"Step p={res['step_prob']:.2f}, N={res['steps']:2d} steps -> "
                f"Trajectory Success={res['trajectory_success']*100:5.1f}%, "
                f"Failure Rate={res['failure_rate']*100:5.1f}%"
            )

    print("\n=== 2. Demo Illusion (pass@k) vs. Production Reliability (pass^k) over 5 Trials ===")
    # Using a 10-step agent where each step has p=0.95 -> single-run trajectory success = 0.95^10 = 0.5987
    traj_p = 0.95 ** 10
    trials_res = repeated_trial_reliability(traj_p, trials=5)
    print(
        f"Single 10-step trajectory success (0.95^10): {trials_res['single_run_prob']*100:.2f}%\n"
        f"pass@5 (succeeds at least once in 5 demo takes): {trials_res['pass_at_k']*100:.2f}%\n"
        f"pass^5 (succeeds on all 5 consecutive production runs): {trials_res['pass_pow_k']*100:.2f}%"
    )

    print("\n=== 3. Context Share & Compaction Threshold ===")
    for step_count in (1, 10, 25, 40):
        ctx = context_dilution_simulation(
            system_prompt_tokens=600,
            avg_tool_Exchange_tokens=1800,
            steps=step_count,
            compaction_threshold_tokens=50000,
        )
        print(
            f"Steps={ctx['steps']:2d}: Total={ctx['total_tokens']:6d} tokens | "
            f"System Prompt Share={ctx['instruction_share_pct']:5.2f}% | "
            f"Compaction Triggered={ctx['compaction_triggered']}"
        )

