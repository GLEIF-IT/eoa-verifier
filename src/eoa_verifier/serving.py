"""Compose KERIpy intake, initial verification, retirement and status delivery."""

import json
import math
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote, urlsplit

import falcon
from hio.base import doing
from hio.core import http, tcp
from hio.core.http import httping as hio_httping
from hio.help import decking
from keri.app import (
    configing,
    habbing,
    httping,
    keeping,
    notifying,
    oobiing,
)
from keri.core import coring, eventing, parsing, routing
from keri.db import basing, dbing
from keri.end import ending
from keri.peer import exchanging
from keri.vc import protocoling
from keri.vdr import credentialing, eventing as veventing, verifying, viring

from .accepting import AcceptanceDoer
from .basing import VerifierBaser
from .delivering import WebhookSender
from .retiring import RetirementDoer
from .statusing import StatusEnd
from .receiving.directing import CesrEnd, Receiver
from .receiving.grants import GrantNotificationDoer
from .verification.constants import ASSOCIATION_SCHEMA
from .verification.coordinating import VerificationCoordinator
from .verification.schema_cache import pin_accepted_schemas
from .verification.worker import EoaVerifierDoer


@dataclass(frozen=True)
class ServiceConfig:
    """Service identity, local storage and initial-verification network settings."""

    # Configured trust root for QVI issuance and delegation; required canonical AID.
    trusted_geda_aid: str
    # Trusted Ethereum endpoint for initial observations; never taken from a credential.
    rpc_url: str
    # Required positive network ID, checked against both association and RPC.
    chain_id: int
    # KERIpy store name; reuse to reopen existing state.
    name: str = "eoa-verifier"
    # Habitat name within the Habery; reuse to retain the service AID.
    alias: str = "verifier"
    # Optional KERIpy store namespace below each store root.
    base: str = ""
    # Root override for KERIpy storage; None uses each KERIpy store’s default/fallback.
    head_dir: str | None = None
    # HTTP bind address; loopback by default.
    host: str = "127.0.0.1"
    # HTTP listening port; zero asks the OS for an ephemeral port.
    http_port: int = 9724
    # Optional KERIpy keystore passcode; excluded from dataclass repr.
    passcode: str | None = field(default=None, repr=False)
    # Optional JSON KERIpy inception options; used only when creating the alias.
    incept_file: str | None = None
    # Use disposable KERIpy stores and remove them on close; intended for tests.
    temp: bool = False
    # Configure both to enable durable acceptance/outbox for one trusted destination.
    webhook_url: str | None = None
    webhook_aid: str | None = None
    # Operational seconds: one in-flight request; backoff range is [lower, 2 * lower].
    webhook_timeout: float = 10.0
    webhook_interval: float = 1.0
    webhook_backoff_base: float = 1.0
    webhook_backoff_cap: float = 150.0

    def __post_init__(self):
        """Reject invalid verification configuration before opening resources."""
        timings = (
            self.webhook_timeout,
            self.webhook_interval,
            self.webhook_backoff_base,
            self.webhook_backoff_cap,
        )
        if not all(math.isfinite(value) and value > 0 for value in timings):
            raise ValueError("webhook timing values must be finite positive seconds")
        if self.webhook_backoff_cap < self.webhook_backoff_base:
            raise ValueError("webhook backoff cap must be at least the base")
        if bool(self.webhook_url) != bool(self.webhook_aid):
            raise ValueError("webhook URL and AID must be configured together")
        if self.webhook_url:
            target = urlsplit(self.webhook_url)
            if (
                target.scheme not in ("http", "https")
                or not target.netloc
                or target.fragment
            ):
                raise ValueError(
                    "webhook must be an absolute HTTP URL without a fragment"
                )
            # Mirror the pinned HIO sender's path/query rendering before signing.
            _, query = hio_httping.updateQargsQuery({}, target.query)
            if (
                quote(target.path or "/") != (target.path or "/")
                or query != target.query
            ):
                raise ValueError("HIO would rewrite the webhook URL path/query")
            if coring.Prefixer(qb64=self.webhook_aid).qb64 != self.webhook_aid:
                raise ValueError("webhook peer must be a canonical AID")
        if not self.rpc_url or self.chain_id <= 0:
            raise ValueError("verification requires an RPC URL and positive chain ID")
        if coring.Prefixer(qb64=self.trusted_geda_aid).qb64 != self.trusted_geda_aid:
            raise ValueError("trusted GEDA must be a canonical AID")


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
                interval=config.webhook_interval,
                backoff_base=config.webhook_backoff_base,
                backoff_cap=config.webhook_backoff_cap,
            )
            doers.extend(
                [
                    AcceptanceDoer(
                        baser=baser,
                        rgy=rgy,
                        destination=config.webhook_url,
                        peer_aid=config.webhook_aid,
                    ),
                    self.sender,
                ]
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
