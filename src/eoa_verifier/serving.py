"""Compose one native receiver and the initial association verifier."""

import json
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path

import falcon
from hio.base import doing
from hio.core import http, tcp
from keri.app import (
    configing,
    habbing,
    httping,
    indirecting,
    keeping,
    notifying,
    oobiing,
    storing,
)
from keri.core import coring
from keri.db import basing
from keri.end import ending
from keri.peer import exchanging
from keri.vc import protocoling
from keri.vdr import credentialing, verifying, viring

from .basing import VerifierBaser
from .receiving.grants import GrantNotificationDoer
from .verification.constants import ASSOCIATION_SCHEMA
from .verification.coordinating import PresentationVerifierDoer
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
    # Native store name; reuse to reopen existing state.
    name: str = "eoa-verifier"
    # Habitat name within the Habery; reuse to retain the service AID.
    alias: str = "verifier"
    # Optional native store namespace below each store root.
    base: str = ""
    # Root override for native storage; None uses each native store’s default/fallback.
    head_dir: str | None = None
    # HTTP bind address; loopback by default.
    host: str = "127.0.0.1"
    # HTTP listening port; zero asks the OS for an ephemeral port.
    http_port: int = 9724
    # Optional native keystore passcode; excluded from dataclass repr.
    passcode: str | None = field(default=None, repr=False)
    # Optional JSON native inception options; used only when creating the alias.
    incept_file: str | None = None
    # Use disposable native stores and remove them on close; intended for tests.
    temp: bool = False


class VerifierService(doing.DoDoer):
    """Own service tasks and shared stores for one HIO lifetime.

    Construction opens nothing. enter opens stores and starts children; exit stops
    children before closing their borrowed stores. Native network Doers alone own
    sockets. Exposed hby/hab/rgy/baser/app are valid only during this lifetime.
    """

    def __init__(self, config, **kwa):
        """Retain configuration and an empty resource stack until HIO enters."""
        self.config = config
        self._resources = ExitStack()
        super().__init__(doers=[], **kwa)

    def enter(self, doers=None, *, temp=None):
        """Compose once per service entry; preserve native extension of child tasks."""
        if doers is not None:
            return super().enter(doers=doers, temp=temp)
        try:
            self._open()
            deeds = super().enter(temp=temp)
            print(
                f"eoa-verifier serving {self.hab.pre} on {self.config.host}:{self.config.http_port}",
                flush=True,
            )
            return deeds
        except BaseException:
            self.exit()
            raise

    def exit(self, deeds=None):
        """Always unwind children first; child removal alone must not close shared stores."""
        remaining = self.deeds if deeds is None else deeds
        errors = []
        while remaining:
            try:
                super().exit(deeds=remaining)
            except BaseException as error:
                # HIO pops a child before closing it; resume with its siblings.
                errors.append(error)
        if deeds is None:
            try:
                self._resources.close()
            except BaseException as error:
                errors.append(error)
        if errors:
            raise BaseExceptionGroup("Service cleanup failed", errors)

    def _open(self):
        """Compose native resources, using a private stack for partial setup failure."""
        config = self.config
        if not config.rpc_url or config.chain_id <= 0:
            raise ValueError("verification requires an RPC URL and positive chain ID")
        if (
            coring.Prefixer(qb64=config.trusted_geda_aid).qb64
            != config.trusted_geda_aid
        ):
            raise ValueError("trusted GEDA must be a canonical AID")
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

        with ExitStack() as resources:
            # Register each store before opening it, including Habery dependencies.
            # A later setup failure therefore cannot leak earlier LMDB handles.
            def store(cls, **extra):
                """Open a native store in the configured namespace and register its cleanup first.

                Return the store. Even a failed reopen leaves a registered close callback;
                temp selects disposable state whose cleanup removes its files.
                """
                obj = cls(
                    name=config.name,
                    base=config.base,
                    temp=config.temp,
                    headDirPath=config.head_dir,
                    reopen=False,
                    **extra,
                )
                resources.callback(obj.close, clear=config.temp)
                obj.reopen()
                return obj

            ks, db, cf = (
                store(keeping.Keeper),
                store(basing.Baser),
                store(configing.Configer),
            )
            hby = habbing.Habery(
                name=config.name,
                base=config.base,
                temp=config.temp,
                ks=ks,
                db=db,
                cf=cf,
                bran=config.passcode,
            )
            pin_accepted_schemas(hby)
            hab = hby.habByName(config.alias) or hby.makeHab(name=config.alias, **inits)
            reger = store(viring.Reger, db=hby.db)
            rgy = credentialing.Regery(
                hby=hby,
                name=config.name,
                base=config.base,
                temp=config.temp,
                reger=reger,
            )
            baser = store(VerifierBaser)
            noter, mbx = store(notifying.Noter), store(storing.Mailboxer)
            notifier = notifying.Notifier(hby=hby, noter=noter)
            exc = exchanging.Exchanger(hby=hby, handlers=[])
            protocoling.loadHandlers(hby=hby, exc=exc, notifier=notifier)
            verifier = verifying.Verifier(hby=hby, reger=reger)
            rep = storing.Respondant(hby=hby, mbx=mbx)
            director = indirecting.MailboxDirector(
                hby=hby,
                topics=[
                    "/receipt",
                    "/replay",
                    "/credential",
                    "/delegate",
                    "/challenge",
                ],
                verifier=verifier,
                exc=exc,
                rep=rep,
            )
            # Direct HTTP, mailbox delivery and Grant embeds share this parser.
            # MailboxDirector alone schedules inbound parsing and escrow processing.
            app = falcon.App()
            ending.loadEnds(app=app, hby=hby, default=hab.pre)
            oobiing.loadEnds(app=app, hby=hby, prefix="/ext")
            app.add_route("/", indirecting.HttpEnd(rxbs=director.ims, mbx=mbx))
            app.add_route("/health", HealthEnd())
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
                rep,
                director,
                http.ServerDoer(server=server),
                GrantNotificationDoer(
                    baser=baser,
                    hby=hby,
                    notifier=notifier,
                    parser=director.parser,
                    expected_association_schema=ASSOCIATION_SCHEMA,
                ),
                PresentationVerifierDoer(
                    baser=baser,
                    rgy=rgy,
                    trusted_geda_aid=config.trusted_geda_aid,
                    association_schema=ASSOCIATION_SCHEMA,
                    eoa_verifier=EoaVerifierDoer(
                        rpc_url=config.rpc_url, chain_id=config.chain_id
                    ),
                ),
            ]
            self.hby, self.hab, self.rgy, self.baser, self.app = (
                hby,
                hab,
                rgy,
                baser,
                app,
            )
            self.doers = doers
            self._resources = resources.pop_all()


class HealthEnd:
    """Expose process liveness only, without asserting evidence or RPC readiness."""

    def on_get(self, req, rep):
        """Set the Falcon response to {"ok": True}; perform no verification or RPC I/O."""
        rep.media = {"ok": True}


def run_service(config: ServiceConfig, *, expire: float = 0.0):
    """Run the composed doers on a real-time HIO scheduler, then close resources.

    expire is the scheduler limit in seconds; zero means no time limit. Normal
    completion returns None. HIO exits children before closing shared stores
    on completion, cancellation or exceptions.
    """
    service = VerifierService(config)
    doing.Doist(limit=expire, tock=0.03125, real=True).do(doers=[service])
