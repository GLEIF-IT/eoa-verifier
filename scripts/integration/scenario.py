"""Standalone witnessed Verifier acceptance/delivery scenario, with no Oracle."""

import json
from importlib.resources import files
from pathlib import Path
from urllib.request import urlopen
from uuid import uuid4

from .artifacts import save_json
from .ceremony import complete_ceremony, open_ceremony
from .environment import (
    present_credential,
    restart_verifier,
    wait_for_status,
)
from .processes import stop
from .services import request_json

# Public deterministic wallet keys for independent-wallet and nonce-reuse cases.
TEST_KEYS = {1: "0x" + "0" * 63 + "1", 2: "0x" + "0" * 63 + "2"}


def run_flow(root: Path, configuration: dict) -> None:
    """Qualify acceptance, nonce rejection, status-event durability and exact revocation.

    Require a fresh scenario but preserve its stores/evidence after completion.
    Each ceremony closes issuer stores before service restart or public reads.
    """
    if (root / "flow-started").exists():
        raise ValueError(
            "Full flow requires a fresh run; use status for this completed scenario"
        )
    (root / "flow-started").write_text("Full flow requires fresh scenario state.\n")
    # Exercise the same exact installed resources served to manual clients.
    for schema in files("eoa_verifier.verification").joinpath("schema_data").iterdir():
        raw = schema.read_bytes()
        said = json.loads(raw)["$id"]
        with urlopen(
            f"http://127.0.0.1:{configuration['schemaPort']}/oobi/{said}", timeout=2
        ) as response:
            assert response.read() == raw
    first = _issue(root, TEST_KEYS[1], str(uuid4()))
    present_credential(root, configuration, first["said"])
    associationStatus = wait_for_status(configuration, first["said"], "accepted")
    _assert_delivery_mode(configuration, associationStatus)
    duplicate = _reject_reused_nonce(root, configuration, first["nonce"])
    storedEvents = (
        request_json(configuration["webhookUrl"])
        if not configuration["localOnly"]
        else None
    )
    if storedEvents is not None:
        stop(root, "receiver")
    restart_verifier(root, configuration)
    reopenedStatus = wait_for_status(configuration, first["said"], "accepted")
    assert (
        reopenedStatus["accountObservation"] == associationStatus["accountObservation"]
    )
    if storedEvents is not None:
        assert request_json(configuration["webhookUrl"]) == storedEvents

    second = _issue(root, TEST_KEYS[1], str(uuid4()))
    present_credential(root, configuration, second["said"])
    wait_for_status(configuration, second["said"], "accepted")
    # Downstream replacement does not revoke the first credential's acceptance.
    assert (
        wait_for_status(configuration, first["said"], "accepted")["eventId"]
        == associationStatus["eventId"]
    )
    for descriptor in (first, second):
        with open_ceremony(root) as ceremony:
            complete_ceremony(ceremony, ceremony.revoke_association(descriptor["said"]))
        present_credential(root, configuration, descriptor["said"])
        wait_for_status(configuration, descriptor["said"], "revoked")
    if storedEvents is not None:
        _assert_stored_events(configuration, first, second, duplicate)
    save_json(
        root / "flow.json",
        {
            "first": first,
            "second": second,
            "rejected": duplicate,
            "accountObservation": associationStatus["accountObservation"],
        },
    )


def _issue(root: Path, wallet_key: str, nonce: str) -> dict:
    """Open one native issuer session and return its exported association descriptor."""
    with open_ceremony(root) as ceremony:
        return complete_ceremony(
            ceremony, ceremony.issue_association(wallet_key, nonce)
        )


def _reject_reused_nonce(root: Path, configuration: dict, nonce: str) -> dict:
    """Prove a valid different-wallet credential cannot reuse any accepted nonce."""
    duplicate = _issue(root, TEST_KEYS[2], nonce)
    present_credential(root, configuration, duplicate["said"])
    rejectedStatus = wait_for_status(configuration, duplicate["said"], "rejected")
    assert (
        rejectedStatus["reason"] == "NONCE_REUSED"
        and rejectedStatus["delivery"] is None
    )
    return duplicate


def _assert_delivery_mode(configuration: dict, associationStatus: dict) -> None:
    """Distinguish target-free acceptance from retried authenticated delivery."""
    if configuration["localOnly"]:
        assert associationStatus["delivery"] is None
    else:
        assert associationStatus["delivery"]["delivered"]
        assert (
            associationStatus["delivery"]["attempts"] >= 2
        )  # Receiver deliberately drops its first ACK.


def _assert_stored_events(
    configuration: dict, first: dict, second: dict, duplicate: dict
) -> None:
    """Require separate accepted/revoked status events and no event for nonce rejection."""
    storedEvents = request_json(configuration["webhookUrl"])
    assert not any(
        json.loads(storedEvent["body"])["associationSaid"] == duplicate["said"]
        for storedEvent in storedEvents
    )
    assert {storedEvent["eventId"] for storedEvent in storedEvents} == {
        f"{descriptor['said']}:{revision}"
        for descriptor in (first, second)
        for revision in (1, 2)
    }
