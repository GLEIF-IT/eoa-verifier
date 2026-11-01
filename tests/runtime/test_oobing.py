"""Optional response-signer OOBI introduction through real HTTP."""

from dataclasses import replace

import falcon
import pytest
from hio.base import doing
from hio.core import http
from keri.app import habbing, oobiing
from keri.end import ending

from tests.support.network import free_port
from tests.support.services import verifier_service


@pytest.mark.parametrize("with_kel", [True, False])
def test_webhook_waits_for_accepted_oobi_key_state(config, with_kel):
    """An HTTP success/resolved marker without the declared AID's validated KEL cannot start delivery."""
    with habbing.openHby(name="target", temp=True) as target:
        hab = target.makeHab(name="target")
        other = target.makeHab(name="other") if not with_kel else None
        port = free_port()
        url = f"http://127.0.0.1:{port}/oobi/{hab.pre}"

        class OtherKelOobi:
            def on_get(self, req, rep, aid):
                rep.content_type = "application/json+cesr"
                rep.set_header(ending.OOBI_AID_HEADER, hab.pre)
                rep.data = bytes(other.makeOwnEvent(sn=0))

        app = falcon.App()
        app.add_route(
            "/oobi/{aid}", ending.OOBIEnd(hby=target) if with_kel else OtherKelOobi()
        )
        server_doer = http.ServerDoer(
            server=http.Server(host="127.0.0.1", port=port, app=app)
        )
        with verifier_service(
            replace(
                config, webhook_url=f"http://127.0.0.1:{port}/hook", webhook_oobi=url
            )
        ) as service:
            assert hab.pre not in service.hby.kevers
            assert service.sender not in service.doers

            def wait(tymth, tock=0.0, **opts):
                yield tock
                while service.hby.db.roobi.get(keys=(url,)) is None:
                    yield 0.01
                # Let the runtime's deferred sender observe the resolution outcome.
                yield 0.05
                record = service.hby.db.roobi.get(keys=(url,))
                assert record.state == oobiing.Result.resolved
                assert (hab.pre in service.hby.kevers) == with_kel
                assert (service.sender in service.doers) == with_kel
                assert service.baser.outbox.cntAll() == 0
                parent.remove([service, server_doer])

            parent = doing.DoDoer(doers=[server_doer, service, doing.doify(wait)])
            doing.Doist(real=True, tock=0.01, limit=3).do(doers=[parent])
            assert parent.done
