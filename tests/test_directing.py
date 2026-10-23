"""HTTP framing and direct-only runtime boundaries; native integration verifies evidence."""

from unittest.mock import patch

import falcon
import pytest
from falcon import testing
from keri.app import habbing, httping, indirecting, storing
from keri.core import eventing

from eoa_verifier.receiving.directing import CesrEnd, Receiver
from eoa_verifier.receiving.grants import GrantNotificationDoer
from native_helpers import running_service


@pytest.fixture
def endpoint():
    incoming = bytearray()
    app = falcon.App()
    app.add_route("/", CesrEnd(incoming))
    return testing.TestClient(app), incoming


def test_post_preserves_native_message_and_attachments(endpoint):
    client, incoming = endpoint
    with habbing.openHab(name="sender", temp=True) as (_, hab):
        stream = hab.makeOwnInception()
        raw = hab.kever.serder.raw
        response = client.simulate_post(
            "/",
            body=raw,
            headers={
                "Content-Type": httping.CESR_CONTENT_TYPE,
                httping.CESR_ATTACHMENT_HEADER: bytes(stream[len(raw) :]).decode(),
            },
        )
        assert response.status_code == 204
        assert incoming == stream
        assert response.headers["cache-control"] == "no-cache"


@pytest.mark.parametrize(
    "body,headers,status",
    [
        ("{}", {"Content-Type": "text/plain"}, 406),
        ("{", {"Content-Type": httping.CESR_CONTENT_TYPE}, 400),
        ("{}", {"Content-Type": httping.CESR_CONTENT_TYPE}, 412),
        ("[]", {"Content-Type": httping.CESR_CONTENT_TYPE, "CESR-ATTACHMENT": ""}, 400),
        ("{}", {"Content-Type": httping.CESR_CONTENT_TYPE, "CESR-ATTACHMENT": ""}, 400),
    ],
)
def test_invalid_post_does_not_enqueue(endpoint, body, headers, status):
    client, incoming = endpoint
    response = client.simulate_post("/", body=body, headers=headers)
    assert response.status_code == status
    assert not incoming


def test_queries_have_no_http_stream_but_put_remains_unfiltered(endpoint):
    client, incoming = endpoint
    query = eventing.query(route="mbx", query={}).raw
    response = client.simulate_post(
        "/",
        body=query,
        headers={"Content-Type": httping.CESR_CONTENT_TYPE, "CESR-ATTACHMENT": ""},
    )
    assert response.status_code == 400
    assert not incoming
    assert response.headers.get("content-type") != "text/event-stream"
    stream = query + query
    response = client.simulate_put("/", body=stream)
    assert response.status_code == 204
    assert incoming == stream
    assert response.headers.get("content-type") != "text/event-stream"
    assert client.simulate_get("/").status_code == 405


def test_runtime_has_one_receiver_and_no_mailbox(config):
    with patch(
        "keri.app.storing.Mailboxer", side_effect=AssertionError("mailbox opened")
    ):
        with running_service(config) as service:
            receivers = [d for d in service.doers if isinstance(d, Receiver)]
            assert len(receivers) == 1
            assert not any(
                isinstance(
                    d,
                    (
                        indirecting.MailboxDirector,
                        indirecting.Poller,
                        storing.Respondant,
                    ),
                )
                for d in service.doers
            )
            grants = next(
                d for d in service.doers if isinstance(d, GrantNotificationDoer)
            )
            assert grants.parser is receivers[0].parser
