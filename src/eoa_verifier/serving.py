"""Compose one native receiver and the initial association verifier."""

import json
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import falcon
from hio.base import doing
from hio.core import http
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
    trusted_geda_aid: str
    rpc_url: str
    chain_id: int
    name: str = "eoa-verifier"
    alias: str = "verifier"
    base: str = ""
    head_dir: str | None = None
    host: str = "127.0.0.1"
    http_port: int = 9724
    passcode: str | None = field(default=None, repr=False)
    incept_file: str | None = None
    temp: bool = False


@dataclass
class ServiceRuntime:
    hby: Any
    hab: Any
    rgy: Any
    baser: VerifierBaser
    app: falcon.App
    doers: list
    resources: ExitStack = field(repr=False)

    def close(self):
        """Close stores after unscheduling doers; safe even if never scheduled."""
        self.resources.close()


def setup_service(config: ServiceConfig) -> ServiceRuntime:
    if not config.rpc_url or config.chain_id <= 0:
        raise ValueError("verification requires an RPC URL and positive chain ID")
    if coring.Prefixer(qb64=config.trusted_geda_aid).qb64 != config.trusted_geda_aid:
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
            hby=hby, name=config.name, base=config.base, temp=config.temp, reger=reger
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
            topics=["/receipt", "/replay", "/credential", "/delegate", "/challenge"],
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
        server = http.Server(host=config.host, port=config.http_port, app=app)
        resources.callback(server.close)
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
        return ServiceRuntime(hby, hab, rgy, baser, app, doers, resources.pop_all())


class HealthEnd:
    def on_get(self, req, rep):
        rep.media = {"ok": True}


def run_service(config: ServiceConfig, *, expire: float = 0.0):
    runtime = setup_service(config)
    try:
        print(
            f"eoa-verifier serving {runtime.hab.pre} on {config.host}:{config.http_port}",
            flush=True,
        )
        doing.Doist(limit=expire, tock=0.03125, real=True).do(doers=runtime.doers)
    finally:
        runtime.close()
