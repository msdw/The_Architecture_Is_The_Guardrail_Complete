"""Runnable reference implementation for Chapter 3:
1. Completes the two-step pedagogical progression from Chapter 1 (DEC-007):
   replaces self-reported `proposal.arguments.get("tags")` with an out-of-band
   `AuthoritativeMetadataStore` lookup inside the Action Gateway.
2. Implements the 5-State Tool Outcome Contract (`SUCCESS`, `NOT_FOUND_OR_EMPTY`,
   `TRANSIENT_FAILURE`, `PERMISSION_DENIED`, `INVALID_INPUT`).
3. Demonstrates Read vs. Write tool separation and JSON-RPC stdout hygiene.
"""
from __future__ import annotations
import io
import json
from contextlib import redirect_stdout
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Protocol


class ToolOutcomeState(Enum):
    """5-State Tool Outcome Contract: prevents models from confusing failures with empty results."""
    SUCCESS = "success"
    NOT_FOUND_OR_EMPTY = "not_found_or_empty"
    TRANSIENT_FAILURE = "transient_failure"
    PERMISSION_DENIED = "permission_denied"
    INVALID_INPUT = "invalid_input"


@dataclass(frozen=True)
class ToolEnvelope:
    state: ToolOutcomeState
    tool_name: str
    payload: dict[str, Any]
    retryable: bool
    error_message: str = ""
    diagnostic_stderr: str = ""


@dataclass(frozen=True)
class VolumeMetadata:
    volume_id: str
    environment: str
    size_gb: int
    unattached_days: int
    tags: dict[str, str]
    attached_to_dr_chain: bool


class AuthoritativeMetadataStore(Protocol):
    """Out-of-band source of truth that the LLM cannot spoof via tool arguments."""
    def get_volume_metadata(self, volume_id: str) -> VolumeMetadata | None: ...


class InMemoryCloudMetadataStore:
    def __init__(self, volumes: dict[str, VolumeMetadata]) -> None:
        self._volumes = dict(volumes)

    def get_volume_metadata(self, volume_id: str) -> VolumeMetadata | None:
        return self._volumes.get(volume_id)


@dataclass(frozen=True)
class NarrowToolProposal:
    tool_name: str
    arguments: dict[str, Any]
    # Note: even if the LLM passes forged tags in `arguments`, the gateway ignores them.


class AuthoritativeActionGateway:
    """Upgraded Chapter 3 Gateway: enforces narrow contracts, 5-state outcomes,
    stdout isolation, and out-of-band metadata verification.
    """

    def __init__(self, metadata_store: AuthoritativeMetadataStore) -> None:
        self._metadata_store = metadata_store
        self._deleted_volumes: list[str] = []

    def inspect_volume(self, volume_id: str) -> ToolEnvelope:
        """Read-only narrow tool: safe to call without human approval."""
        if not volume_id.startswith("vol-"):
            return ToolEnvelope(
                state=ToolOutcomeState.INVALID_INPUT,
                tool_name="inspect_volume",
                payload={},
                retryable=False,
                error_message="volume_id must start with 'vol-'.",
            )
        meta = self._metadata_store.get_volume_metadata(volume_id)
        if meta is None:
            return ToolEnvelope(
                state=ToolOutcomeState.NOT_FOUND_OR_EMPTY,
                tool_name="inspect_volume",
                payload={"volume_id": volume_id},
                retryable=False,
                error_message=f"Volume {volume_id} does not exist in inventory.",
            )
        return ToolEnvelope(
            state=ToolOutcomeState.SUCCESS,
            tool_name="inspect_volume",
            payload={
                "volume_id": meta.volume_id,
                "environment": meta.environment,
                "unattached_days": meta.unattached_days,
                "has_owner_tag": bool(meta.tags.get("owner")),
                "attached_to_dr_chain": meta.attached_to_dr_chain,
            },
            retryable=False,
        )

    def delete_unattached_staging_volume(self, proposal: NarrowToolProposal) -> ToolEnvelope:
        """Write tool: verifies resource tags and DR status out-of-band against
        the authoritative store, ignoring any self-reported tags in `proposal.arguments`.
        """
        volume_id = str(proposal.arguments.get("volume_id", ""))
        if not volume_id.startswith("vol-"):
            return ToolEnvelope(
                state=ToolOutcomeState.INVALID_INPUT,
                tool_name="delete_unattached_staging_volume",
                payload={},
                retryable=False,
                error_message="Invalid volume_id format.",
            )

        # CRITICAL UPGRADE FROM CH. 1: Fetch metadata out-of-band, never from proposal.arguments
        auth_meta = self._metadata_store.get_volume_metadata(volume_id)
        if auth_meta is None:
            return ToolEnvelope(
                state=ToolOutcomeState.NOT_FOUND_OR_EMPTY,
                tool_name="delete_unattached_staging_volume",
                payload={"volume_id": volume_id},
                retryable=False,
                error_message=f"Cannot delete non-existent volume {volume_id}.",
            )

        if auth_meta.environment != "staging":
            return ToolEnvelope(
                state=ToolOutcomeState.PERMISSION_DENIED,
                tool_name="delete_unattached_staging_volume",
                payload={"volume_id": volume_id, "environment": auth_meta.environment},
                retryable=False,
                error_message="Tool scope restricted to staging environment only.",
            )

        if not auth_meta.tags.get("owner") or auth_meta.attached_to_dr_chain:
            return ToolEnvelope(
                state=ToolOutcomeState.PERMISSION_DENIED,
                tool_name="delete_unattached_staging_volume",
                payload={
                    "volume_id": volume_id,
                    "authoritative_tags": auth_meta.tags,
                    "attached_to_dr_chain": auth_meta.attached_to_dr_chain,
                },
                retryable=False,
                error_message=(
                    "Blocked by authoritative policy: volume lacks 'owner' tag or belongs to DR chain."
                ),
            )

        # Capture any accidental stdout print inside legacy driver so JSON-RPC channel stays clean
        stray_stdout = io.StringIO()
        with redirect_stdout(stray_stdout):
            print(f"[driver-debug] deleting {volume_id}...")
            self._deleted_volumes.append(volume_id)

        return ToolEnvelope(
            state=ToolOutcomeState.SUCCESS,
            tool_name="delete_unattached_staging_volume",
            payload={"deleted_volume_id": volume_id},
            retryable=False,
            diagnostic_stderr=stray_stdout.getvalue().strip(),
        )


if __name__ == "__main__":
    store = InMemoryCloudMetadataStore(
        {
            "vol-77b1": VolumeMetadata(
                volume_id="vol-77b1",
                environment="staging",
                size_gb=4096,
                unattached_days=16,
                tags={},  # Untagged in authoritative cloud inventory!
                attached_to_dr_chain=True,
            ),
            "vol-88c2": VolumeMetadata(
                volume_id="vol-88c2",
                environment="staging",
                size_gb=100,
                unattached_days=20,
                tags={"owner": "load-test-team"},
                attached_to_dr_chain=False,
            ),
        }
    )
    gateway = AuthoritativeActionGateway(store)

    # Even if a hallucinating or prompt-injected LLM spoofs `tags={"owner": "admin"}` in its proposal:
    spoofed_proposal = NarrowToolProposal(
        tool_name="delete_unattached_staging_volume",
        arguments={"volume_id": "vol-77b1", "tags": {"owner": "admin"}},
    )
    blocked = gateway.delete_unattached_staging_volume(spoofed_proposal)
    assert blocked.state == ToolOutcomeState.PERMISSION_DENIED
    assert "lacks 'owner' tag" in blocked.error_message

    valid_proposal = NarrowToolProposal(
        tool_name="delete_unattached_staging_volume",
        arguments={"volume_id": "vol-88c2"},
    )
    allowed = gateway.delete_unattached_staging_volume(valid_proposal)
    assert allowed.state == ToolOutcomeState.SUCCESS
    assert allowed.diagnostic_stderr == "[driver-debug] deleting vol-88c2..."
    # Verify that serializing the envelope produces valid JSON uncorrupted by the print() call
    serialized = json.dumps({"state": allowed.state.value, "payload": allowed.payload})
    assert json.loads(serialized)["payload"]["deleted_volume_id"] == "vol-88c2"
    print("Chapter 3 authoritative gateway & 5-state contract verification passed.")

