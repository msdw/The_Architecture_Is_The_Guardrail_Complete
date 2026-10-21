"""Runnable reference implementation for Chapter 4:
1. Pre-ranking ACL document filtering for production RAG ("a model cannot leak what it never received").
2. Capability Taint Tracking enforcing the Rule of Two (Lethal Trifecta prevention):
   Once untrusted external content enters the session context, external communication and
   unapproved state-mutating tools are deterministically revoked for the remainder of the run.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, Flag, auto
from typing import Any


class DataTrustLevel(Enum):
    TRUSTED_INTERNAL = "trusted_internal"
    UNTRUSTED_EXTERNAL = "untrusted_external"


class ToolCapability(Flag):
    NONE = 0
    READ_PRIVATE_DATA = auto()
    READ_UNTRUSTED_CONTENT = auto()
    MUTATE_INTERNAL_STATE = auto()
    SEND_EXTERNAL_COMMUNICATION = auto()


@dataclass(frozen=True)
class DocumentChunk:
    doc_id: str
    text: str
    allowed_roles: frozenset[str]
    trust_level: DataTrustLevel
    relevance_score: float


def retrieve_with_pre_prompt_acl(
    corpus: list[DocumentChunk],
    caller_roles: frozenset[str],
    top_k: int = 3,
) -> list[DocumentChunk]:
    """Filter by ACL *before* ranking and *before* building the prompt context."""
    authorized = [
        chunk for chunk in corpus if chunk.allowed_roles & caller_roles
    ]
    authorized.sort(key=lambda c: c.relevance_score, reverse=True)
    return authorized[:top_k]


@dataclass(frozen=True)
class ScopedTool:
    name: str
    capabilities: ToolCapability


@dataclass
class TaintTrackedSession:
    session_id: str
    caller_roles: frozenset[str]
    has_accessed_private_data: bool = False
    is_tainted_by_untrusted_content: bool = False
    taint_sources: list[str] = field(default_factory=list)
    audit_events: list[str] = field(default_factory=list)

    def record_context_ingestion(self, source_id: str, trust: DataTrustLevel, is_private: bool) -> None:
        if is_private:
            self.has_accessed_private_data = True
        if trust == DataTrustLevel.UNTRUSTED_EXTERNAL:
            self.is_tainted_by_untrusted_content = True
            self.taint_sources.append(source_id)
            self.audit_events.append(
                f"TAINT_ACQUIRED from {source_id}: revoking direct external/mutation capabilities."
            )


class CapabilityTaintGateway:
    """Enforces the Rule of Two: a session that has ingested both private data and
    untrusted external content cannot invoke external communication or unapproved writes.
    """

    def __init__(self, tools: dict[str, ScopedTool]) -> None:
        self._tools = tools

    def authorize_tool_call(self, session: TaintTrackedSession, tool_name: str) -> tuple[bool, str]:
        tool = self._tools.get(tool_name)
        if tool is None:
            return False, f"Unknown tool: {tool_name}"

        # Check if this tool will expose the session to private or untrusted data
        if ToolCapability.READ_PRIVATE_DATA in tool.capabilities:
            session.has_accessed_private_data = True
        if ToolCapability.READ_UNTRUSTED_CONTENT in tool.capabilities:
            session.record_context_ingestion(
                source_id=f"tool:{tool_name}",
                trust=DataTrustLevel.UNTRUSTED_EXTERNAL,
                is_private=False,
            )

        # Rule of Two enforcement: if tainted by untrusted content, block outbound & mutation tools
        restricted_caps = (
            ToolCapability.SEND_EXTERNAL_COMMUNICATION | ToolCapability.MUTATE_INTERNAL_STATE
        )
        if session.is_tainted_by_untrusted_content and (tool.capabilities & restricted_caps):
            reason = (
                f"BLOCKED_BY_TAINT_TRACKER: Tool '{tool_name}' requires {tool.capabilities}, "
                f"but session is tainted by untrusted sources {session.taint_sources}."
            )
            session.audit_events.append(reason)
            return False, reason

        session.audit_events.append(f"ALLOWED: {tool_name}")
        return True, "Allowed"


if __name__ == "__main__":
    # 1. Verify pre-prompt ACL filtering
    chunks = [
        DocumentChunk("doc-exec-comp", "CEO salary details", frozenset({"hr_admin"}), DataTrustLevel.TRUSTED_INTERNAL, 0.99),
        DocumentChunk("doc-runbook", "Standard support SOP", frozenset({"support_agent"}), DataTrustLevel.TRUSTED_INTERNAL, 0.85),
    ]
    visible = retrieve_with_pre_prompt_acl(chunks, caller_roles=frozenset({"support_agent"}))
    assert [c.doc_id for c in visible] == ["doc-runbook"], "Unauthorized high-relevance doc leaked!"

    # 2. Verify Capability Taint Tracker blocking indirect prompt injection exfiltration
    tools = {
        "read_customer_vault": ScopedTool("read_customer_vault", ToolCapability.READ_PRIVATE_DATA),
        "read_external_email": ScopedTool("read_external_email", ToolCapability.READ_UNTRUSTED_CONTENT),
        "send_outbound_webhook": ScopedTool("send_outbound_webhook", ToolCapability.SEND_EXTERNAL_COMMUNICATION),
    }
    gateway = CapabilityTaintGateway(tools)
    sess = TaintTrackedSession(session_id="sess-401", caller_roles=frozenset({"support_agent"}))

    ok1, _ = gateway.authorize_tool_call(sess, "read_customer_vault")
    assert ok1 is True and sess.has_accessed_private_data is True

    # Now the agent reads an untrusted customer email containing an indirect prompt injection
    ok2, _ = gateway.authorize_tool_call(sess, "read_external_email")
    assert ok2 is True and sess.is_tainted_by_untrusted_content is True

    # The injected payload instructs the LLM to exfiltrate vault data via send_outbound_webhook
    ok3, msg3 = gateway.authorize_tool_call(sess, "send_outbound_webhook")
    assert ok3 is False
    assert "BLOCKED_BY_TAINT_TRACKER" in msg3
    print("Chapter 4 ACL & Capability Taint Tracker verification passed.")

