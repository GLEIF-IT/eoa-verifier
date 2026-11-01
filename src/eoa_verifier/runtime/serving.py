"""Compose KERIpy intake, initial verification, retirement and status delivery."""

import json
from collections import deque
from pathlib import Path

import falcon
from hio.base import doing
from hio.core import http, tcp
from hio.help import decking
from keri.app import (
    configing,
    habbing,
    httping,
    keeping,
    notifying,
    oobiing,
)
from keri.core import eventing, parsing, routing
from keri.db import basing, dbing
from keri.end import ending
from keri.peer import exchanging
from keri.vc import protocoling
from keri.vdr import credentialing, eventing as veventing, verifying, viring

from ..associations.accepting import AcceptanceDoer
from ..associations.retiring import RetirementDoer
from ..associations.statusing import StatusEnd
from ..delivery.delivering import WebhookSender
from ..persistence.basing import VerifierBaser
from ..receiving.directing import CesrEnd, Receiver
from ..receiving.grants import GrantNotificationDoer
from ..verification.constants import ASSOCIATION_SCHEMA
from ..verification.coordinating import VerificationCoordinator
from ..verification.schema_cache import pin_accepted_schemas
from ..verification.worker import EoaVerifierDoer
from .config import ServiceConfig


class VerifierService(doing.DoDoer):
    """Own service tasks and sockets while borrowing the caller's open stores."""

    def __init__(self, config, *, hby, rgy, baser, noter, **kwa):
        """Wire KERIpy verification and HTTP tasks without owning shared stores.

        config is ServiceConfig; hby/rgy are open KERIpy Habery/Regery instances,
        baser is VerifierBaser, and noter is the KERIpy notification store. The
        caller must keep all of them open until HIO child shutdown completes.
        Construction pins schemas and creates the configured habitat if absent;
        inception options apply only to that creation. HIO network Doers own
        their sockets. kwa is passed to HIO DoDoer.
        """
        baser.bind_verification_scope(
            trusted_geda_aid=config.trusted_geda_aid, chain_id=config.chain_id
        )
        self.config = config
        inits = {
            "transferable": True,
            "icount": 1,
            "isith": "1",
            "ncount": 1,
            "nsith": "1",
            "wits": [],
            "toad": 0,
        }
        if config.incept_file:
            extra = json.loads(Path(config.incept_file).read_text())
            if not isinstance(extra, dict):
                raise ValueError("incept file must contain a JSON object")
            inits.update(extra)

        pin_accepted_schemas(hby)
        hab = hby.habByName(config.alias) or hby.makeHab(name=config.alias, **inits)
        notifier = notifying.Notifier(hby=hby, noter=noter)
        exc = exchanging.Exchanger(hby=hby, handlers=[])
        protocoling.loadHandlers(hby=hby, exc=exc, notifier=notifier)
        verifier = verifying.Verifier(hby=hby, reger=rgy.reger)
        cues = decking.Deck()
        router = routing.Router()
        rvy = routing.Revery(db=hby.db, rtr=router, lax=True, local=False)
        kvy = eventing.Kevery(
            db=hby.db, cues=cues, rvy=rvy, lax=True, local=False, direct=False
        )
        kvy.registerReplyRoutes(router)
        tvy = veventing.Tevery(
            reger=rgy.reger, db=hby.db, rvy=rvy, cues=cues, lax=True, local=False
        )
        tvy.registerReplyRoutes(router)
        parser = parsing.Parser(
            framed=True, kvy=kvy, tvy=tvy, exc=exc, rvy=rvy, vry=verifier
        )
        # HTTP and Grant embeds share KERIpy processors; Receiver owns their scheduling.
        receiver = Receiver(
            parser,
            msg_tock=hby.tocks["mailboxMsg"],
            escrow_tock=hby.tocks["mailboxEscrow"],
        )
        app = falcon.App()
        ending.loadEnds(app=app, hby=hby, default=hab.pre)
        oobiing.loadEnds(app=app, hby=hby, prefix="/ext")
        app.add_route("/", CesrEnd(msgs=receiver.msgs))
        app.add_route("/health", HealthEnd())
        app.add_route("/v1/associations/{said}/status", StatusEnd(baser))
        server = http.Server(
            host=config.host,
            port=config.http_port,
            app=app,
            # Explicit TCP address preserves port zero; retain HTTP’s timeout.
            servant=tcp.Server(
                ha=(config.host, config.http_port),
                tymeout=http.Server.Tymeout,
                bufsize=8096,
            ),
        )
        oobiery = oobiing.Oobiery(hby=hby, clienter=httping.Clienter())
        doers = [
            *oobiery.doers,
            receiver,
            http.ServerDoer(server=server),
            GrantNotificationDoer(
                baser=baser,
                hby=hby,
                notifier=notifier,
                parser=parser,
            ),
            VerificationCoordinator(
                baser=baser,
                rgy=rgy,
                trusted_geda_aid=config.trusted_geda_aid,
                association_schema=ASSOCIATION_SCHEMA,
                eoa_verifier=EoaVerifierDoer(
                    rpc_url=config.rpc_url, chain_id=config.chain_id
                ),
            ),
        ]
        doers.append(RetirementDoer(baser=baser, rgy=rgy))
        self.sender = None
        if config.webhook_url:
            self.sender = WebhookSender(
                baser=baser,
                hab=hab,
                timeout=config.webhook_timeout,
                max_attempts=config.webhook_max_attempts,
                interval=config.webhook_interval,
                backoff_base=config.webhook_backoff_base,
                backoff_cap=config.webhook_backoff_cap,
            )
            doers.append(self.sender)
        doers.append(
            AcceptanceDoer(
                baser=baser,
                rgy=rgy,
                destination=config.webhook_url,
                peer_aid=config.webhook_aid,
            )
        )
        self.hby, self.hab, self.rgy, self.baser, self.app = (
            hby,
            hab,
            rgy,
            baser,
            app,
        )
        super().__init__(doers=doers, **kwa)

    def exit(self, deeds: deque | None = None):
        """Attempt every child cleanup and propagate failures; stores belong to the caller."""
        remaining = self.deeds if deeds is None else deeds
        errors = []
        while remaining:
            try:
                super().exit(deeds=remaining)
            except BaseException as error:
                # HIO pops a child before closing it; resume with its siblings.
                errors.append(error)
        if errors:
            raise BaseExceptionGroup("Service cleanup failed", errors)


class HealthEnd:
    """Expose process liveness only, without asserting evidence or RPC readiness."""

    def on_get(self, req, rep):
        """Handle GET /health without parameters or authentication.

        req is the Falcon request; rep receives HTTP 200 and application/json
        {"ok": true}. This liveness response performs no verification or RPC I/O
        and does not imply that dependencies are ready. Returns None.
        """
        rep.media = {"ok": True}


def run_service(config: ServiceConfig, *, expire: float = 0.0):
    """Run the service inside KERIpy store contexts and a real-time HIO scheduler.

    config supplies identity, paths, passcode and network policy. expire is the
    scheduler limit in seconds; zero runs without a limit. Explicit config.temp
    controls every store: persistent state remains on disk after shutdown, while
    temporary contexts remove their files. Supplied Habery/Regery stores are
    borrowed, so no second store-owning Doer is installed.

    Earlier contexts close if later startup fails. During normal shutdown HIO
    stops children before the contexts close their stores. Startup and cleanup
    errors propagate; KERIpy contexts govern failures inside an individual open.
    Returns None after the scheduler stops.
    """
    options = dict(name=config.name, base=config.base, headDirPath=config.head_dir)
    with (
        keeping.openKS(temp=config.temp, **options) as ks,
        basing.openDB(temp=config.temp, **options) as db,
        configing.openCF(temp=config.temp, **options) as cf,
        viring.openReger(temp=config.temp, db=db, **options) as reger,
        dbing.openLMDB(cls=VerifierBaser, temp=config.temp, **options) as baser,
        dbing.openLMDB(cls=notifying.Noter, temp=config.temp, **options) as noter,
    ):
        hby = habbing.Habery(
            name=config.name,
            base=config.base,
            temp=config.temp,
            ks=ks,
            db=db,
            cf=cf,
            bran=config.passcode,
            free=False,
        )
        rgy = credentialing.Regery(
            hby=hby, name=config.name, base=config.base, temp=config.temp, reger=reger
        )
        service = VerifierService(config, hby=hby, rgy=rgy, baser=baser, noter=noter)
        print(
            f"eoa-verifier serving {service.hab.pre} on {config.host}:{config.http_port}",
            flush=True,
        )
        doing.Doist(limit=expire, tock=0.03125, real=True).do(doers=[service])
