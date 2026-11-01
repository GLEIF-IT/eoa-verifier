"""KERIpy HTTP signature interoperability, optional responses and accepted keys."""

from contextlib import ExitStack

import pytest
from keri.app import habbing
from keri.end import ending

from eoa_verifier.delivery.authing import AuthenticationError, HttpSignatures
from eoa_verifier.delivery.keys import ServiceKeys
from eoa_verifier.delivery.signatures import FIELDS


def message():
    """Use fixed HTTP context; transport does not impose an ACK payload schema."""
    return dict(
        method="POST",
        target="https://oracle.example/hook?chain=1",
        body=b'{"eventId":"one"}',
    )


def test_request_and_optional_response_use_keripy_headers(peers):
    """The AID is declared in keyid; no destination identity or custom attributes."""
    sender, receiver = peers
    context = message()
    headers = sender.sign(**context)
    inp = ending.desiginput(headers["signature-input"].encode())[0]
    assert tuple(inp.fields) == FIELDS
    assert inp.keyid == sender.keys.aid
    assert inp.nonce is inp.expires is inp.context is None
    assert not any(name.startswith("eoa-") for name in headers)
    assert (
        receiver.verify(**context, headers=headers, expected_aid=sender.keys.aid)
        == sender.keys.aid
    )
    response = dict(context, body=b'{"stored":true}')
    signed = receiver.sign(**response)
    assert sender.verify_optional(**response, headers=signed) == receiver.keys.aid
    assert sender.verify_optional(**response, headers={}) is None
    assert (
        sender.verify_optional(
            **response, headers={"content-digest": "ordinary-metadata"}
        )
        is None
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("body", b'{"eventId":"changed"}'),
        ("method", "GET"),
        ("target", "https://oracle.example/elsewhere?chain=1"),
    ],
)
def test_covered_context_cannot_be_changed(peers, field, value):
    """The signature binds the body digest and actual HTTP method/path."""
    sender, receiver = peers
    context = message()
    headers = sender.sign(**context)
    with pytest.raises(AuthenticationError):
        receiver.verify(**dict(context, **{field: value}), headers=headers)
    assert receiver.verify(**context, headers=headers) == sender.keys.aid


def test_signature_reuse_has_no_transport_state(peers):
    """Only application event handling decides whether repeated bytes add effects."""
    sender, receiver = peers
    headers = sender.sign(**message())
    for _ in range(2):
        assert receiver.verify(**message(), headers=headers) == sender.keys.aid


def test_rotation_uses_keripy_accepted_key_state(peers):
    """New keys work only after rotation acceptance; superseded signatures fail."""
    sender, receiver = peers
    old = sender.sign(**message())
    rotation = sender.keys.hab.rotate()
    headers = sender.sign(**message())
    with pytest.raises(AuthenticationError, match="signature"):
        receiver.verify(**message(), headers=headers)
    receiver.keys.hab.psr.parse(ims=bytearray(rotation))
    with pytest.raises(AuthenticationError, match="signature"):
        receiver.verify(**message(), headers=old)
    assert receiver.verify(**message(), headers=headers) == sender.keys.aid


def test_unknown_and_unauthorized_signers_fail(peers):
    """Knowing a key permits verification, not authorization as Oracle's producer."""
    sender, receiver = peers
    with pytest.raises(AuthenticationError, match="untrusted"):
        receiver.verify(
            **message(),
            headers=sender.sign(**message()),
            expected_aid=receiver.keys.aid,
        )
    with habbing.openHby(name="unknown", temp=True) as hby:
        stranger = HttpSignatures(ServiceKeys(hby.makeHab(name="unknown")))
        with pytest.raises(AuthenticationError, match="key state"):
            sender.verify_optional(**message(), headers=stranger.sign(**message()))


@pytest.mark.parametrize("header", ["signature", "signature-input", "content-digest"])
@pytest.mark.parametrize("change", ["remove", "corrupt"])
def test_partial_or_changed_response_headers_never_fall_back(peers, header, change):
    """Any signature header opts the response into strict signature verification."""
    sender, receiver = peers
    headers = receiver.sign(**message())
    if change == "remove":
        del headers[header]
    else:
        headers[header] = "invalid"
    with pytest.raises(AuthenticationError):
        sender.verify_optional(**message(), headers=headers)


def test_keyid_and_required_coverage_cannot_be_substituted(peers):
    """Reject substitutions of the signer identity or required digest coverage in signed input."""
    sender, receiver = peers
    headers = sender.sign(**message())
    for changed in (
        headers["signature-input"].replace(sender.keys.aid, receiver.keys.aid),
        headers["signature-input"].replace('"content-digest"', '"content-type"'),
    ):
        with pytest.raises(AuthenticationError):
            receiver.verify(
                **message(), headers=dict(headers, **{"signature-input": changed})
            )


def test_empty_signed_response(peers):
    """Verify the digest and signature of a zero-length body through the pure signature adapter."""
    sender, receiver = peers
    context = dict(message(), body=b"")
    assert (
        sender.verify_optional(**context, headers=receiver.sign(**context))
        == receiver.keys.aid
    )


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
            sender = HttpSignatures(
                keys=ServiceKeys(remote),
            )
            headers = sender.sign(**message())
            aid = runtime.hab.pre
            lifetime.close()
            lifetime = ExitStack()
            runtime = lifetime.enter_context(entered_service(config))
            assert runtime.hab.pre == aid
            receiver = HttpSignatures(
                keys=ServiceKeys(runtime.hab),
            )
            receiver.verify(**message(), headers=headers)
    finally:
        lifetime.close()
