"""receiving/test_directing.py."""

import falcon
import pytest
from falcon import testing
from hio.base import doing
from hio.help import decking
from keri.app import habbing, httping
from keri.core import eventing

from eoa_verifier.receiving.directing import CesrEnd
from tests.support.services import verifier_service


@pytest.fixture
def endpoint():
    """Return an in-process Falcon client and its completed-request deck."""
    incoming = decking.Deck()
    app = falcon.App()
    app.add_route("/", CesrEnd(incoming))
    return testing.TestClient(app), incoming


def test_post_preserves_json_message_and_cesr_attachments(endpoint):
    """POST reconstructs a JSON message with CESR attachments and acknowledges intake."""
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
        assert incoming.popleft() == stream
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
    """Bad HTTP framing returns its documented error without adding parser bytes."""
    client, incoming = endpoint
    response = client.simulate_post("/", body=body, headers=headers)
    assert response.status_code == status
    assert not incoming


def test_queries_have_no_http_stream_but_put_remains_unfiltered(endpoint):
    """Reject POST queries, preserve raw PUT bytes and never open an SSE stream."""
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
    assert incoming.popleft() == stream
    assert response.headers.get("content-type") != "text/event-stream"
    assert client.simulate_get("/").status_code == 405


@pytest.mark.parametrize("method", ["POST", "PUT"])
def test_incomplete_request_does_not_block_later_messages(config, method):
    """Discard incomplete request bytes; parse both messages in the next valid PUT."""
    with (
        verifier_service(config) as service,
        habbing.openHab(name="sender", temp=True) as (_, hab),
    ):
        client = testing.TestClient(service.app)
        inception = hab.makeOwnInception()
        if method == "POST":
            # Declare a controller-signature attachment but omit its signature.
            response = client.simulate_post(
                "/",
                body=hab.kever.serder.raw,
                headers={
                    "Content-Type": httping.CESR_CONTENT_TYPE,
                    "CESR-ATTACHMENT": "-AAB",
                },
            )
        else:
            # A finite request cannot satisfy the serialization length it declares.
            response = client.simulate_put(
                "/", body=b'{"v":"KERI10JSONffffff_","t":"ixn"}'
            )
        assert response.status_code == 204  # Intake, not evidence acceptance.
        interaction = hab.interact()
        assert client.simulate_put("/", body=inception + interaction).status_code == 204

        doing.Doist(tock=0.01, limit=0.2).do(doers=[service])

        assert service.hby.kevers[hab.pre].sn == 1


def test_http_cannot_advance_the_services_own_kel(config):
    """A correctly signed own-AID event from HTTP remains KERIpy misfit evidence."""
    with verifier_service(config) as service:
        hab = service.hab
        event = eventing.interact(pre=hab.pre, dig=hab.kever.serder.said, sn=1)
        stream = eventing.messagize(event, sigers=hab.sign(ser=event.raw))
        assert (
            testing.TestClient(service.app).simulate_put("/", body=stream).status_code
            == 204
        )

        doing.Doist(tock=0.01, limit=0.2).do(doers=[service])

        assert hab.kever.sn == 0
        assert service.hby.db.misfits.get(keys=(hab.pre, event.snh))
