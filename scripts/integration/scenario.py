"""Standalone witnessed Verifier acceptance/delivery scenario, with no Oracle."""

import json
from pathlib import Path
from importlib.resources import files
from urllib.request import urlopen
from uuid import uuid4

from .artifacts import save_json
from .ceremony import complete_ceremony, open_ceremony
from .environment import (
    present_credential,
    request_json,
    restart_verifier,
    wait_for_status,
)
from .processes import stop

TEST_KEYS = {1: "0x" + "0" * 63 + "1", 2: "0x" + "0" * 63 + "2"}


def run_flow(root: Path, configuration: dict) -> None:
    """Qualify acceptance, nonce rejection, receipt durability and exact retirement.

    Require a fresh scenario but preserve its stores/evidence after completion.
    Each ceremony closes issuer stores before service restart or public reads.
    """
    if (root / "flow.json").exists():
        raise ValueError(
            "Full flow requires a fresh run; use status for this completed scenario"
        )
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
    accepted = wait_for_status(configuration, first["said"], "accepted")
    _assert_delivery_mode(configuration, accepted)
    duplicate = _reject_reused_nonce(root, configuration, first["nonce"])
    receipts = (
        request_json(configuration["webhookUrl"])
        if not configuration["localOnly"]
        else None
    )
    if receipts is not None:
        stop(root, "receiver")
    restart_verifier(root, configuration)
    reopened = wait_for_status(configuration, first["said"], "accepted")
    assert reopened["accountObservation"] == accepted["accountObservation"]
    if receipts is not None:
        assert request_json(configuration["webhookUrl"]) == receipts

    second = _issue(root, TEST_KEYS[1], str(uuid4()))
    present_credential(root, configuration, second["said"])
    wait_for_status(configuration, second["said"], "accepted")
    # Downstream replacement does not revoke the first credential's acceptance.
    assert (
        wait_for_status(configuration, first["said"], "accepted")["eventId"]
        == accepted["eventId"]
    )
    for descriptor in (first, second):
        with open_ceremony(root) as ceremony:
            complete_ceremony(ceremony, ceremony.revoke_association(descriptor["said"]))
        present_credential(root, configuration, descriptor["said"])
        wait_for_status(configuration, descriptor["said"], "revoked")
    if receipts is not None:
        _assert_receipts(configuration, first, second, duplicate)
    save_json(
        root / "flow.json",
        {
            "first": first,
            "second": second,
            "rejected": duplicate,
            "accountObservation": accepted["accountObservation"],
        },
    )


def _issue(root: Path, wallet_key: str, nonce: str) -> dict:
    """Open one native issuer session and return its exported association descriptor."""
    with open_ceremony(root) as ceremony:
        return complete_ceremony(
            ceremony, ceremony.issue_association(wallet_key, nonce)
        )


def _reject_reused_nonce(root: Path, configuration: dict, nonce: str) -> dict:
    """Prove a valid different-wallet credential cannot reuse an accepted pair."""
    duplicate = _issue(root, TEST_KEYS[2], nonce)
    present_credential(root, configuration, duplicate["said"])
    rejected = wait_for_status(configuration, duplicate["said"], "rejected")
    assert rejected["reason"] == "NONCE_REUSED" and rejected["delivery"] is None
    return duplicate


def _assert_delivery_mode(configuration: dict, accepted: dict) -> None:
    """Distinguish target-free acceptance from retried authenticated delivery."""
    if configuration["localOnly"]:
        assert accepted["delivery"] is None
    else:
        assert accepted["delivery"]["acknowledged"]
        assert (
            accepted["delivery"]["attempts"] >= 2
        )  # Receiver deliberately drops its first ACK.


def _assert_receipts(
    configuration: dict, first: dict, second: dict, duplicate: dict
) -> None:
    """Require separate accepted/revoked receipts and no event for nonce rejection."""
    events = request_json(configuration["webhookUrl"])
    assert not any(
        json.loads(event["body"])["associationSaid"] == duplicate["said"]
        for event in events
    )
    assert {event["eventId"] for event in events} == {
        f"{descriptor['said']}:{revision}"
        for descriptor in (first, second)
        for revision in (1, 2)
    }
