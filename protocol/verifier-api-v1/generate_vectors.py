"""Regenerate public encoding fixtures; never creates production key material."""

import argparse
import base64
import hashlib
import json
import subprocess
from copy import deepcopy

from conformance import PROFILE, ROOT, binding, digest, signing_bytes
from keri.core import Signer, coring, eventing

ORACLE_REVISION = "77849caae048381aee96b42f75053368d8d24c53"


def nonce(n):
    return base64.urlsafe_b64encode(bytes([n]) * 32).decode().rstrip("=")


def said(label):
    return coring.Diger(ser=label.encode()).qb64


def identity(offset):
    seeds = [bytes(range(offset + i, offset + i + 32)) for i in range(3)]
    signers = [Signer(raw=s, transferable=True) for s in seeds]
    inception = eventing.incept(
        keys=[signers[0].verfer.qb64],
        ndigs=[coring.Diger(ser=signers[1].verfer.qb64b).qb64],
        code="E",
    )
    rotation = eventing.rotate(
        pre=inception.pre,
        keys=[signers[1].verfer.qb64],
        dig=inception.said,
        sn=1,
        ndigs=[coring.Diger(ser=signers[2].verfer.qb64b).qb64],
    )
    public = {
        "aid": inception.pre,
        "publicTestSeeds": [s.hex() for s in seeds],
        "inception": json.loads(inception.raw),
        "rotation": json.loads(rotation.raw),
        "inceptionSignature": signers[0].sign(inception.raw, index=0).qb64,
        "rotationSignature": signers[1].sign(rotation.raw, index=0).qb64,
        "keys": [s.verfer.qb64 for s in signers],
    }
    return public, signers


def build(oracle_dir):
    carrier = ROOT / "carrier"
    carrier.mkdir(exist_ok=True)
    manifest = {
        "repository": "https://github.com/GLEIF-IT/vlei-oracle",
        "revision": ORACLE_REVISION,
        "files": {},
    }
    for name in ("test-vector.json", "association.json"):
        path = "protocol/external-association-v1/eoa-v1/" + name
        raw = subprocess.check_output(
            ["git", "-C", oracle_dir, "show", ORACLE_REVISION + ":" + path]
        )
        (carrier / name).write_bytes(raw)
        manifest["files"][name] = {
            "path": path,
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
    (ROOT / "provenance.json").write_bytes(
        json.dumps(manifest, indent=2).encode() + b"\n"
    )
    old = json.loads((carrier / "test-vector.json").read_text())
    verifier, vs = identity(0)
    oracle, os = identity(40)
    facts = {
        "issuerAid": old["typedData"]["message"]["issuerAid"],
        "leSaid": old["typedData"]["message"]["leVleiSaid"],
        "qviSaid": said("qvi"),
        "extId": old["typedData"]["message"]["extId"],
        "issuance": {
            "registrySaid": said("registry"),
            "telSequence": "0",
            "telDigest": said("issuance"),
            "anchorSequence": "12",
            "anchorDigest": said("anchor"),
        },
    }
    account = {
        "chainId": "1",
        "blockNumber": "100",
        "blockHash": "0x" + "ab" * 32,
        "observedAt": "1800000003",
        "codeClass": "empty",
        "codeDigest": hashlib.sha256(b"").hexdigest(),
    }
    creds = []
    for n, cred in enumerate(
        [old["associationSaid"], facts["leSaid"], facts["qviSaid"]]
    ):
        creds.append(
            {
                "credentialSaid": cred,
                "registrySaid": facts["issuance"]["registrySaid"]
                if n == 0
                else said("registry" + str(n)),
                "telSequence": "0",
                "telDigest": facts["issuance"]["telDigest"]
                if n == 0
                else said("tel" + str(n)),
                "issuerAid": facts["issuerAid"] if n == 0 else said("issuer" + str(n)),
                "kelSequence": "12",
                "kelDigest": facts["issuance"]["anchorDigest"]
                if n == 0
                else said("kel" + str(n)),
                "startedAt": "1800000001",
                "completedAt": "1800000002",
                "peers": [
                    {
                        "peerAid": said("peer" + str(n)),
                        "kelDigest": hashlib.sha256(
                            ("kel response" + str(n)).encode()
                        ).hexdigest(),
                        "telDigest": hashlib.sha256(
                            ("tel response" + str(n)).encode()
                        ).hexdigest(),
                        "completedAt": "1800000002",
                    }
                ],
            }
        )
    assessment = {
        "version": "1",
        "profile": PROFILE,
        "verifierAid": verifier["aid"],
        "associationSaid": old["associationSaid"],
        "revision": "1",
        "decision": {
            "outcome": "valid",
            "reasonCode": "VALID",
            "facts": facts,
            "provenance": {
                "policy": "eoa-v1",
                "evidenceDigest": hashlib.sha256(
                    b"synthetic encoding evidence 1"
                ).hexdigest(),
            },
        },
        "observations": {"account": account, "credentials": creds},
    }
    assessment["decisionDigest"] = digest(assessment["decision"])
    stream = nonce(90)
    events = []
    for revision, outcome, reason in [
        (1, "valid", "VALID"),
        (2, "invalid", "ACCOUNT_CONTRACT"),
        (3, "valid", "VALID"),
        (4, "invalid", "ASSOCIATION_REVOKED"),
    ]:
        a = deepcopy(assessment)
        a["revision"] = str(revision)
        a["decision"].update(outcome=outcome, reasonCode=reason)
        a["decision"]["provenance"]["evidenceDigest"] = hashlib.sha256(
            f"synthetic encoding evidence {revision}".encode()
        ).hexdigest()
        if revision == 2:
            a["observations"]["account"].update(
                codeClass="contract", codeDigest=hashlib.sha256(b"\x60\x00").hexdigest()
            )
        if revision == 4:
            a["observations"]["credentials"][0].update(
                telSequence="1", telDigest=said("revocation")
            )
        a["decisionDigest"] = digest(a["decision"])
        e = {"streamId": stream, "eventSequence": str(revision), "assessment": a}
        e["eventId"] = digest(e)
        events.append(e)
    envelopes = {}
    count = 0

    def envelope(
        name, who, payload, method, target, request=None, status=None, rotated=False
    ):
        nonlocal count
        count += 1
        pub, keys, peer = (
            (verifier, vs, oracle) if who == "verifier" else (oracle, os, verifier)
        )
        epoch = pub["rotation"] if rotated else pub["inception"]
        protected = {
            "version": "1",
            "kind": "response" if request else "request",
            "signerAid": pub["aid"],
            "audience": peer["aid"],
            "establishment": {
                "sequence": str(int(epoch["s"], 16)),
                "digest": epoch["d"],
            },
            "method": method,
            "target": target,
            "issuedAt": "1800000004" if request else "1800000000",
            "expiresAt": "1800000030",
            "nonce": nonce(count),
            "payloadDigest": digest(payload),
            "requestDigest": digest(request) if request else None,
            "requestNonce": request["protected"]["nonce"] if request else None,
            "status": status,
        }
        env = {
            "protected": protected,
            "payload": payload,
            "signature": keys[int(rotated)]
            .sign(signing_bytes(protected), index=0)
            .qb64,
        }
        envelopes[name] = {
            "envelope": env,
            "signingHex": signing_bytes(protected).hex(),
            "wireSha256": digest(env),
        }
        return env

    e = events[0]
    req = envelope("event", "verifier", e, "POST", "/v1/verifier-events")
    ack = {
        "acceptanceId": e["eventId"],
        "eventId": e["eventId"],
        "payloadDigest": digest(e),
        "outcome": "applied",
    }
    envelope("ack", "oracle", ack, "POST", "/v1/verifier-events", req, "200")
    envelope("rotatedEvent", "verifier", e, "POST", "/v1/verifier-events", rotated=True)
    path = "/v1/assessments/" + assessment["associationSaid"]
    req = envelope("assessmentQuery", "oracle", {}, "GET", path)
    envelope("storedAssessment", "verifier", assessment, "GET", path, req, "200")
    req = envelope("factsQuery", "oracle", {}, "GET", path + "/facts")
    envelope(
        "facts",
        "verifier",
        {
            k: assessment[k]
            for k in ("version", "profile", "verifierAid", "associationSaid")
        }
        | {"facts": facts},
        "GET",
        path + "/facts",
        req,
        "200",
    )
    refresh = envelope(
        "refreshRequest",
        "oracle",
        {
            "associationSaid": assessment["associationSaid"],
            "chainId": "1",
            "minRevision": "1",
        },
        "POST",
        path + "/refresh",
    )
    handle = {
        "requestId": digest(refresh),
        "associationSaid": assessment["associationSaid"],
        "originRequestDigest": digest(refresh),
        "originRequestNonce": refresh["protected"]["nonce"],
        "expiresAt": "1800000030",
        "state": "pending",
    }
    envelope(
        "refreshAccepted", "verifier", handle, "POST", path + "/refresh", refresh, "202"
    )
    pollpath = "/v1/refreshes/" + handle["requestId"]
    poll = envelope("refreshPoll", "oracle", {}, "GET", pollpath)
    envelope("refreshPending", "verifier", handle, "GET", pollpath, poll, "202")
    envelope(
        "refreshComplete",
        "verifier",
        handle | {"state": "complete", "assessment": assessment},
        "GET",
        pollpath,
        poll,
        "200",
    )
    replaypath = "/v1/events?after=0&limit=20&stream=" + stream
    req = envelope("replayQuery", "oracle", {}, "GET", replaypath)
    envelope(
        "replay",
        "verifier",
        {
            "streamId": stream,
            "after": "0",
            "next": "4",
            "highWater": "4",
            "events": events,
        },
        "GET",
        replaypath,
        req,
        "200",
    )
    for status, code in [
        ("400", "MALFORMED"),
        ("401", "AUTHENTICATION_FAILED"),
        ("403", "FORBIDDEN"),
        ("404", "NOT_FOUND"),
        ("409", "CONFLICT"),
        ("413", "TOO_LARGE"),
        ("422", "UNSUPPORTED"),
        ("503", "UNAVAILABLE"),
    ]:
        envelope(
            "error" + status,
            "verifier",
            {"code": code, "diagnostic": "fixture error", "retryable": status == "503"},
            "GET",
            replaypath,
            req,
            status,
        )
    result = {
        "purpose": "Encoding fixtures with public test keys and synthetic credential references; no native credential acceptance claim.",
        "verifier": verifier,
        "oracle": oracle,
        "binding": binding(facts),
        "events": events,
        "envelopes": envelopes,
        "reducerTraces": [
            {
                "events": ["1", "1", "2", "1", "3", "4"],
                "outcomes": [
                    "applied",
                    "applied",
                    "applied",
                    "applied",
                    "applied",
                    "applied",
                ],
                "finalRevision": "4",
            },
            {
                "events": ["4", "1", "3", "2"],
                "outcomes": ["applied", "stale", "stale", "stale"],
                "finalRevision": "4",
            },
        ],
    }
    (ROOT / "vectors.json").write_bytes(json.dumps(result, indent=2).encode() + b"\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--oracle-dir",
        required=True,
        help="Checkout containing the pinned commit (read with git show)",
    )
    build(parser.parse_args().oracle_dir)
