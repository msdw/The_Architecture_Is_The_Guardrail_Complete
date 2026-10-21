"""Runnable reference implementation for Chapter 2:
Demonstrates why a Level 2 Bounded State Machine (deterministic transitions + narrow
LLM extraction/classification nodes) outperforms an unconstrained Level 3 open ReAct loop
for structured operational workflows (refund triage).
"""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Callable


class TriageState(Enum):
    CLASSIFY_INTENT = "classify_intent"
    VERIFY_ELIGIBILITY = "verify_eligibility"
    EXECUTE_AUTO_REFUND = "execute_auto_refund"
    ESCALATE_TO_HUMAN = "escalate_to_human"
    TERMINATED = "terminated"


@dataclass(frozen=True)
class RefundTicket:
    ticket_id: str
    customer_id: str
    order_id: str
    message_text: str


@dataclass(frozen=True)
class OrderRecord:
    order_id: str
    amount_usd: float
    days_since_purchase: int
    already_refunded: bool


@dataclass
class WorkflowContext:
    ticket: RefundTicket
    state: TriageState = TriageState.CLASSIFY_INTENT
    intent: str | None = None
    order: OrderRecord | None = None
    outcome: str = ""
    llm_calls_used: int = 0


def run_bounded_refund_workflow(
    ctx: WorkflowContext,
    classify_fn: Callable[[str], str],
    fetch_order_fn: Callable[[str], OrderRecord | None],
    issue_refund_fn: Callable[[str, float], str],
    max_transitions: int = 5,
) -> WorkflowContext:
    """Deterministic state machine where the LLM is only invoked atCLASSIFY_INTENT."""
    transitions = 0
    while ctx.state != TriageState.TERMINATED:
        transitions += 1
        if transitions > max_transitions:
            ctx.outcome = "HALTED: Transition budget exceeded"
            ctx.state = TriageState.TERMINATED
            break

        if ctx.state == TriageState.CLASSIFY_INTENT:
            # Single bounded LLM call: classify intent into a strict enum
            ctx.llm_calls_used += 1
            ctx.intent = classify_fn(ctx.ticket.message_text)
            if ctx.intent == "refund_request":
                ctx.state = TriageState.VERIFY_ELIGIBILITY
            else:
                ctx.outcome = f"SKIPPED: Non-refund intent ({ctx.intent})"
                ctx.state = TriageState.TERMINATED

        elif ctx.state == TriageState.VERIFY_ELIGIBILITY:
            # Pure deterministic Python & database lookup—zero LLM tokens or hallucination risk
            ctx.order = fetch_order_fn(ctx.ticket.order_id)
            if ctx.order is None or ctx.order.already_refunded:
                ctx.outcome = "REJECTED: Order missing or already refunded"
                ctx.state = TriageState.TERMINATED
            elif ctx.order.days_since_purchase <= 14 and ctx.order.amount_usd <= 50.0:
                ctx.state = TriageState.EXECUTE_AUTO_REFUND
            else:
                ctx.state = TriageState.ESCALATE_TO_HUMAN

        elif ctx.state == TriageState.EXECUTE_AUTO_REFUND:
            assert ctx.order is not None
            receipt = issue_refund_fn(ctx.order.order_id, ctx.order.amount_usd)
            ctx.outcome = f"AUTO_REFUNDED: {receipt}"
            ctx.state = TriageState.TERMINATED

        elif ctx.state == TriageState.ESCALATE_TO_HUMAN:
            assert ctx.order is not None
            ctx.outcome = (
                f"ESCALATED: Order {ctx.order.order_id} (${ctx.order.amount_usd:.2f}, "
                f"{ctx.order.days_since_purchase}d old) exceeds auto-refund policy bounds"
            )
            ctx.state = TriageState.TERMINATED

    return ctx


if __name__ == "__main__":
    # Verify both auto-refund and policy-escalation paths deterministically
    orders_db = {
        "ORD-101": OrderRecord("ORD-101", amount_usd=35.0, days_since_purchase=6, already_refunded=False),
        "ORD-202": OrderRecord("ORD-202", amount_usd=140.0, days_since_purchase=19, already_refunded=False),
    }

    t1 = RefundTicket("TCK-1", "CUST-9", "ORD-101", "Hi, my adapter arrived broken, please refund.")
    res1 = run_bounded_refund_workflow(
        WorkflowContext(ticket=t1),
        classify_fn=lambda _: "refund_request",
        fetch_order_fn=orders_db.get,
        issue_refund_fn=lambda oid, amt: f"rfnd_{oid}_${amt:.2f}",
    )
    assert res1.outcome == "AUTO_REFUNDED: rfnd_ORD-101_$35.00"
    assert res1.llm_calls_used == 1

    t2 = RefundTicket("TCK-2", "CUST-8", "ORD-202", "I want a full refund on my monitor.")
    res2 = run_bounded_refund_workflow(
        WorkflowContext(ticket=t2),
        classify_fn=lambda _: "refund_request",
        fetch_order_fn=orders_db.get,
        issue_refund_fn=lambda oid, amt: f"rfnd_{oid}_${amt:.2f}",
    )
    assert "ESCALATED: Order ORD-202 ($140.00, 19d old)" in res2.outcome
    assert res2.llm_calls_used == 1
    print("Chapter 2 state-machine verification passed:", res1.outcome, "|", res2.outcome)

