"""delivery/test_authing.py."""

from contextlib import ExitStack
from unittest.mock import patch

import pytest
from keri.app import habbing
from keri.help import helping

from eoa_verifier.delivery.authing import AuthenticationError, ServiceAuthenticator


def message():
    """Return fixed HTTP context for transport-only tests; payload is not a new schema."""
    return dict(
        method="POST",
        target="https://oracle.example/hook?chain=1",
        action="status",
        body=b'{"eventId":"one"}',
    )


def test_signed_request_and_correlated_response(peers):
    """Authenticate a KERI AID-signed request and a response bound to its attempt/body."""
    sender, receiver = peers
    context = message()
    headers, sent = sender.sign(**context)
    received = receiver.verify(**context, headers=headers)
    assert received == sent
    ack = dict(
        context,
        action="ack",
        body=b'{"ack":"one"}',
        request=received.reference,
        status=200,
    )
    headers, _ = receiver.sign(**ack)
    with pytest.raises(AuthenticationError):
        sender.verify(**dict(ack, request="another attempt"), headers=headers)
    with pytest.raises(AuthenticationError):
        sender.verify(**dict(ack, status=500), headers=headers)
    assert sender.verify(**ack, headers=headers).peer == receiver.hab.pre


@pytest.mark.parametrize(
    "field,value",
    [
        ("body", b'{"eventId":"changed"}'),
        ("method", "GET"),
        ("target", "https://elsewhere.example/hook?chain=1"),
        ("target", "https://oracle.example/elsewhere?chain=1"),
        ("target", "https://oracle.example/hook?chain=2"),
        ("action", "revoke"),
    ],
)
def test_tampering_does_not_consume_nonce(peers, field, value):
    """Changed HTTP/body context fails, leaving the authentic attempt usable."""
    sender, receiver = peers
    context = message()
    headers, _ = sender.sign(**context)
    with pytest.raises(AuthenticationError):
        receiver.verify(**dict(context, **{field: value}), headers=headers)
    receiver.verify(**context, headers=headers)


def test_restart_rejects_replay_but_allows_new_attempt(peers):
    """A stored nonce survives KERIpy store reopen; a freshly signed retry is distinct."""
    sender, receiver = peers
    context = message()
    headers, _ = sender.sign(**context)
    receiver.verify(**context, headers=headers)
    receiver.baser.close()
    receiver.baser.reopen()
    with pytest.raises(AuthenticationError, match="replay"):
        receiver.verify(**context, headers=headers)
    headers, _ = sender.sign(**context)
    receiver.verify(**context, headers=headers)


def test_rotation_uses_keripy_accepted_key_state(peers):
    """Same-AID rotation works after KERIpy event acceptance; old-key attempts fail."""
    sender, receiver = peers
    context = message()
    old, _ = sender.sign(**context)
    rotation = sender.hab.rotate()
    headers, _ = sender.sign(**context)
    with pytest.raises(AuthenticationError, match="signature"):
        receiver.verify(**context, headers=headers)
    receiver.hab.psr.parse(ims=bytearray(rotation))
    with pytest.raises(AuthenticationError, match="signature"):
        receiver.verify(**context, headers=old)
    receiver.verify(**context, headers=headers)


def test_expiry_and_unknown_peer(peers):
    """Expired attempts and peers outside configuration are rejected before nonce claims."""
    sender, receiver = peers
    context = message()
    headers, _ = sender.sign(**context)
    now = helping.nowUTC()
    from datetime import timedelta

    with patch("keri.help.helping.nowUTC", return_value=now + timedelta(seconds=61)):
        with pytest.raises(AuthenticationError, match="lifetime"):
            receiver.verify(**context, headers=headers)
    receiver.peer_aid = receiver.hab.pre
    with pytest.raises(AuthenticationError, match="peer"):
        receiver.verify(**context, headers=headers)


def test_signed_error_response_authenticates_without_implying_delivery(peers):
    """Authentication covers the actual status; delivery policy decides success."""
    sender, receiver = peers
    context = message()
    headers, sent = sender.sign(**context)
    received = receiver.verify(**context, headers=headers)
    response = {
        "method": context["method"],
        "target": context["target"],
        "action": "ack",
        "body": b'{"error":"unavailable"}',
        "request": received.reference,
        "status": 500,
    }
    headers, _ = receiver.sign(**response)
    with pytest.raises(AuthenticationError, match="mismatch"):
        sender.verify(**dict(response, status=200), headers=headers)
    assert received.reference == sent.reference
    assert sender.verify(**response, headers=headers).peer == receiver.hab.pre


@pytest.mark.parametrize(
    "header,value",
    [
        ("signature", "invalid"),
        ("signature-input", "invalid"),
        ("eoa-audience", "another-service"),
        ("content-digest", "sha-256=:invalid:"),
    ],
)
def test_malformed_or_changed_headers_fail_closed(peers, header, value):
    """Reject malformed KERI AID signatures and covered-field changes before claiming replay state."""
    sender, receiver = peers
    context = message()
    headers, _ = sender.sign(**context)
    with pytest.raises(AuthenticationError):
        receiver.verify(**context, headers=dict(headers, **{header: value}))
    receiver.verify(**context, headers=headers)


def test_rotated_peer_state_survives_service_restart(tmp_path):
    """Reopen actual service stores and authenticate with persisted rotated peer key state."""
    from keri import core

    from eoa_verifier.runtime.config import ServiceConfig
    from tests.support.services import entered_service

    config = ServiceConfig(
        trusted_geda_aid=core.Signer().verfer.qb64,
        rpc_url="http://127.0.0.1:1",
        chain_id=31337,
        head_dir=str(tmp_path),
        http_port=0,
    )
    lifetime = ExitStack()
    runtime = lifetime.enter_context(entered_service(config))
    try:
        with habbing.openHby(name="remote", temp=True) as hby:
            remote = hby.makeHab(name="remote")
            runtime.hby.psr.parse(ims=bytearray(remote.makeOwnEvent(sn=0)))
            runtime.hby.psr.parse(ims=bytearray(remote.rotate()))
            sender = ServiceAuthenticator(
                hab=remote, baser=runtime.baser, peer_aid=runtime.hab.pre
            )
            headers, _ = sender.sign(**message())
            aid = runtime.hab.pre
            lifetime.close()
            lifetime = ExitStack()
            runtime = lifetime.enter_context(entered_service(config))
            assert runtime.hab.pre == aid
            receiver = ServiceAuthenticator(
                hab=runtime.hab, baser=runtime.baser, peer_aid=remote.pre
            )
            receiver.verify(**message(), headers=headers)
    finally:
        lifetime.close()


def test_signed_http_request_and_ack(peers):
    """Carry KERI AID signatures through Falcon HTTP parsing without a delivery implementation."""
    import falcon
    from falcon.testing import TestClient

    sender, receiver = peers
    context = message()

    class Endpoint:
        """Test-only receiver that authenticates actual method/path/query and returns an ACK."""

        def on_post(self, req, rep):
            """Verify received bytes, then sign a test ACK; no application acceptance is claimed."""
            target = "https://oracle.example" + req.relative_uri
            received = receiver.verify(
                method=req.method,
                target=target,
                action="status",
                body=req.bounded_stream.read(),
                headers=req.headers,
            )
            body = b'{"ack":"one"}'
            headers, _ = receiver.sign(
                method=req.method,
                target=target,
                body=body,
                action="ack",
                request=received.reference,
                status=200,
            )
            rep.data = body
            rep.set_headers(headers)

    app = falcon.App()
    app.add_route("/hook", Endpoint())
    headers, sent = sender.sign(**context)
    response = TestClient(app).simulate_post(
        "/hook?chain=1", headers=headers, body=context["body"]
    )
    assert response.status_code == 200
    sender.verify(
        action="ack",
        request=sent.reference,
        method=context["method"],
        target=context["target"],
        body=response.content,
        headers=response.headers,
        status=response.status_code,
    )
