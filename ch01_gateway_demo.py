"""Executable reference code for BOOK-001, Chapter 1, Section 1.4.

Demonstrates the structural shift from a prompt-guarded loop to a minimal
Deterministic Action Gateway that enforces capability bounds, environment locks,
and step budgets outside the language model.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class ActionStatus(Enum):
    EXECUTED = "executed"
    HELD_FOR_APPROVAL = "held_for_approval"
    BLOCKED_BY_POLICY = "blocked_by_policy"
    STEP_BUDGET_EXCEEDED = "step_budget_exceeded"


@dataclass(frozen=True)
class ToolProposal:
    """A structured intent emitted by the probabilistic planner (LLM)."""
    tool_name: str
    arguments: dict[str, Any]
    reasoning_trace: str = ""


@dataclass(frozen=True)
class ToolSpec:
    """Deterministic metadata and execution contract registered in the control plane."""
    name: str
    handler: Callable[..., dict[str, Any]]
    mutates_state: bool
    requires_approval_in_envs: frozenset[str] = frozenset({"prod", "staging"})


@dataclass
class ExecutionSession:
    """External state tracked by the harness—never delegated to the model's context."""
    session_id: str
    environment: str
    max_steps: int = 25
    steps_taken: int = 0
    audit_log: list[dict[str, Any]] = field(default_factory=list)


class DeterministicActionGateway:
    """Control-plane boundary standing between the model's proposals and real systems."""

    def __init__(self, registry: dict[str, ToolSpec]) -> None:
        self._registry = registry

    def dispatch(self, session: ExecutionSession, proposal: ToolProposal) -> dict[str, Any]:
        session.steps_taken += 1

        if session.steps_taken > session.max_steps:
            return self._record(
                session,
                proposal,
                ActionStatus.STEP_BUDGET_EXCEEDED,
                detail=f"Halted: step {session.steps_taken} exceeds max_steps={session.max_steps}.",
            )

        spec = self._registry.get(proposal.tool_name)
        if spec is None:
            return self._record(
                session,
                proposal,
                ActionStatus.BLOCKED_BY_POLICY,
                detail=f"Unknown or unapproved tool: {proposal.tool_name!r}.",
            )

        # Deterministic invariant: state-mutating calls on untagged resources or protected
        # environments cannot bypass approval, regardless of what the prompt or context says.
        if spec.mutates_state and session.environment in spec.requires_approval_in_envs:
            tags = proposal.arguments.get("tags", {})
            if not tags.get("owner"):
                return self._record(
                    session,
                    proposal,
                    ActionStatus.HELD_FOR_APPROVAL,
                    detail="State-mutating action on resource without 'owner' tag requires human sign-off.",
                )

        result = spec.handler(**proposal.arguments)
        return self._record(session, proposal, ActionStatus.EXECUTED, detail=result)

    @staticmethod
    def _record(
        session: ExecutionSession,
        proposal: ToolProposal,
        status: ActionStatus,
        detail: Any,
    ) -> dict[str, Any]:
        entry = {
            "step": session.steps_taken,
            "tool": proposal.tool_name,
            "args": proposal.arguments,
            "status": status.value,
            "detail": detail,
        }
        session.audit_log.append(entry)
        return entry


if __name__ == "__main__":
    # Register two tools: one read-only, one destructive
    registry = {
        "list_unattached_volumes": ToolSpec(
            name="list_unattached_volumes",
            handler=lambda region: {"volumes": ["vol-09a8", "vol-77b1"]},
            mutates_state=False,
        ),
        "delete_volume": ToolSpec(
            name="delete_volume",
            handler=lambda volume_id, tags: {"deleted": volume_id},
            mutates_state=True,
            requires_approval_in_envs=frozenset({"prod", "staging"}),
        ),
    }

    gateway = DeterministicActionGateway(registry)
    session = ExecutionSession(session_id="run-2026-1021", environment="staging", max_steps=20)

    # Simulate step 38 after context compaction: the model proposes deleting an untagged volume
    proposal = ToolProposal(
        tool_name="delete_volume",
        arguments={"volume_id": "vol-77b1", "tags": {}},
        reasoning_trace="Volume has been unattached for 14 days; deleting to save cost.",
    )

    outcome = gateway.dispatch(session, proposal)
    print(f"Status: {outcome['status']}")
    print(f"Detail: {outcome['detail']}")

