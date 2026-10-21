"""Verification script for Chapter 2 quantitative claims:
1. Latency compounding across the Spectrum of Agency (Level 0 to Level 3).
2. Quadratic prompt token accumulation across an N-step loop.
3. Effective Cost per Successful Task (ECST) including human fallback/triage cost.
"""
from __future__ import annotations


def step_latency_ms(ttft_ms: float, output_tokens: int, itl_ms: float, tool_ms: float) -> float:
    return ttft_ms + (output_tokens * itl_ms) + tool_ms


def cumulative_input_tokens(base_prompt: int, step_obs_tokens: int, steps: int) -> int:
    """In an uncompacted loop, step i processes base_prompt + (i - 1) * step_obs_tokens."""
    total = 0
    for i in range(1, steps + 1):
        total += base_prompt + (i - 1) * step_obs_tokens
    return total


def effective_cost_per_successful_task(
    api_cost_per_run: float,
    p_success: float,
    human_fallback_cost: float,
) -> float:
    """ECST = (C_run + (1 - P_success) * C_fallback) / P_success"""
    return (api_cost_per_run + (1.0 - p_success) * human_fallback_cost) / p_success


def main() -> None:
    # 1. Step latency verification
    p50_step_ms = step_latency_ms(ttft_ms=450, output_tokens=180, itl_ms=15.0, tool_ms=250)
    w_step_ms = step_latency_ms(ttft_ms=1400, output_tokens=300, itl_ms=28.0, tool_ms=800)
    assert p50_step_ms == 3400.0, f"Expected 3400.0, got {p50_step_ms}"
    assert w_step_ms == 10600.0, f"Expected 10600.0, got {w_step_ms}"

    print(f"Single step p50 latency: {p50_step_ms:.0f} ms ({p50_step_ms/1000:.2f} s)")
    print(f"Single step tail (stressed) latency: {w_step_ms:.0f} ms ({w_step_ms/1000:.2f} s)")

    # 2. Spectrum of Agency comparison (N=1 router, N=3 state machine, N=8 open loop)
    base_prompt = 1200
    step_obs = 1500
    input_price_per_1m = 3.00   # $3.00 / 1M input tokens
    output_price_per_1m = 15.00  # $15.00 / 1M output tokens
    output_tokens_per_step = 180
    human_triage_cost = 15.00   # 12 minutes of engineer/ops review at $75/hr loaded rate

    patterns = [
        ("Level 1: Structured Router / Extractor", 1, 0.98),
        ("Level 2: Bounded State Machine (3 steps)", 3, 0.92),
        ("Level 3: Open Autonomous Loop (8 steps)", 8, 0.66),
    ]

    print("\n--- Spectrum of Agency Metrics ---")
    for name, steps, p_succ in patterns:
        cum_in = cumulative_input_tokens(base_prompt, step_obs, steps)
        cum_out = steps * output_tokens_per_step
        api_cost = (cum_in / 1_000_000) * input_price_per_1m + (cum_out / 1_000_000) * output_price_per_1m
        p50_total_s = (steps * p50_step_ms) / 1000.0
        ecst = effective_cost_per_successful_task(api_cost, p_succ, human_triage_cost)
        print(
            f"{name}: steps={steps}, cum_in={cum_in:,} tok, cum_out={cum_out:,} tok, "
            f"p50_lat={p50_total_s:.2f}s, raw_api=${api_cost:.4f}, "
            f"P_succ={p_succ*100:.0f}%, ECST=${ecst:.2f}"
        )


if __name__ == "__main__":
    main()

