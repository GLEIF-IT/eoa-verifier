"""Run-owned KERI witness identities and exact installed schema hosting.

Native contexts own stores and HIO owns sockets. The daemon serves one witness
for automated qualification or six for the manual environment; issuance retains
the existing one-witness credential profile.
"""

import json
from pathlib import Path
from urllib.request import urlopen

from .artifacts import save_json
from .processes import launch, wait_ready


def make_identity(root: Path, name: str, *, transferable: bool = True):
    """Create/reopen a fixture AID and return its public identifier before closing."""
    from keri.app import habbing

    with habbing.openHby(name=name, headDirPath=str(root), temp=False) as hby:
        hab = hby.habByName(name) or hby.makeHab(name=name, transferable=transferable)
        return hab.pre


def initialize(root: Path, config: dict) -> None:
    """Prepare independent witness, Verifier and receiver identities under root."""
    import subprocess
    import sys
    from importlib.metadata import version

    config["versions"] = {
        "python": sys.version.split()[0],
        **{name: version(name) for name in ("eoa-verifier", "gleif_keri", "gleif_hio")},
        "anvil": subprocess.check_output(
            [config["anvil"], "--version"], text=True, timeout=5
        ).strip(),
    }
    for index, w in enumerate(config["witnesses"]):
        aid = make_identity(root / f"witness-{index}", "witness", transferable=False)
        w.update(aid=aid, url=f"http://127.0.0.1:{w['port']}")
    config["verifierAid"] = make_identity(root / "services", "verifier")
    config["receiverAid"] = make_identity(root / "receiver", "receiver")
    save_json(root / "run.json", config)


def infrastructure(root: Path, config: dict) -> None:
    """Launch owned witnesses/schema hosting and verify each expected OOBI."""
    launch(
        root,
        "infrastructure",
        [
            config["python"],
            "-m",
            "scripts.integration.env",
            "_infrastructure",
            "--run-dir",
            str(root),
        ],
        port=config["witnesses"][0]["port"],
        cwd=Path(config["tool"]).parents[2],
    )
    for w in config["witnesses"]:
        wait_ready(
            root,
            "infrastructure",
            lambda w=w: bool(
                urlopen(
                    w["url"] + "/oobi/" + w["aid"] + "/controller", timeout=2
                ).read()
            ),
        )


def serve_infrastructure(root: Path, config: dict) -> None:
    """Serve native witness tasks and packaged schema bytes until shutdown."""
    from contextlib import ExitStack
    from importlib.resources import files

    import falcon
    from hio.base import doing
    from hio.core import http
    from keri.app import habbing, indirecting

    schemas = {
        json.loads(p.read_bytes())["$id"]: p.read_bytes()
        for p in files("eoa_verifier.verification").joinpath("schema_data").iterdir()
    }

    class Schema:
        """Expose only the already accepted packaged schemas for local issuers."""

        def on_get(self, req, rep, said):
            """Return exact schema bytes or 404; never fetch or synthesize a schema."""
            if said not in schemas:
                raise falcon.HTTPNotFound()
            rep.data = schemas[said]
            rep.content_type = "application/schema+json"

    with ExitStack() as stack:
        doers = []
        for index, w in enumerate(config["witnesses"]):
            hby = stack.enter_context(
                habbing.openHby(
                    name="witness",
                    headDirPath=str(root / f"witness-{index}"),
                    temp=False,
                )
            )
            doers.extend(
                indirecting.setupWitness(
                    hby=hby, alias="witness", tcpPort=None, httpPort=w["port"]
                )
            )
            hab = hby.habByName("witness")
            hby.psr.parse(ims=hab.makeEndRole(eid=hab.pre))
            hby.psr.parse(ims=hab.makeLocScheme(url=w["url"]))
        app = falcon.App()
        app.add_route("/oobi/{said}", Schema())
        server = http.Server(host="127.0.0.1", port=config["schemaPort"], app=app)
        doers.append(http.ServerDoer(server=server))
        doing.Doist(real=True, tock=0.01).do(doers=doers)
