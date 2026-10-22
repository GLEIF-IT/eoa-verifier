"""Executable v1 contract model, NOT service authentication or persistence.

Keys passed to check_envelope are fixture trust state. Production adapters must
obtain them from native accepted KERI state and persist nonce/reducer operations.
"""

import hashlib
import json
import re
from pathlib import Path

from eth_utils import keccak
from jsonschema import Draft202012Validator
from keri.core import Siger, Verfer

ROOT = Path(__file__).resolve().parent
SCHEMA = json.loads((ROOT / "schema.json").read_text())
PROFILE = "vlei-external-association/eoa/v1"
DOMAIN = b"EOA-VERIFIER-API/1\n"
MAX_BODY = 1_048_576
REVOKED = {"ASSOCIATION_REVOKED", "SOURCE_REVOKED"}
REASONS = {
    "valid": {"VALID"},
    "invalid": REVOKED
    | {"ASSOCIATION_INVALID", "SOURCE_INVALID", "PROOF_INVALID", "ACCOUNT_CONTRACT"},
    "unavailable": {
        "EVIDENCE_UNAVAILABLE",
        "SOURCE_UNAVAILABLE",
        "RPC_UNAVAILABLE",
        "NETWORK_MISMATCH",
        "FRESHNESS_UNAVAILABLE",
    },
}


def canonical(value):
    def check(item):
        if item is None or type(item) is bool:
            return
        if isinstance(item, str) and all(32 <= ord(c) <= 126 for c in item):
            return
        if isinstance(item, list):
            for element in item:
                check(element)
            return
        if isinstance(item, dict) and all(isinstance(k, str) for k in item):
            for key, element in item.items():
                check(key)
                check(element)
            return
        raise ValueError("outside canonical JSON subset")

    check(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def parse(raw):
    if len(raw) > MAX_BODY:
        raise ValueError("body too large")

    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise ValueError("duplicate key")
            result[k] = v
        return result

    result = json.loads(raw, object_pairs_hook=pairs)
    if canonical(result) != raw:
        raise ValueError("noncanonical wire bytes")
    return result


def validate(shape, value):
    schema = {"$ref": "#/$defs/" + shape, "$defs": SCHEMA["$defs"]}
    Draft202012Validator(schema).validate(value)


def signing_bytes(protected):
    return DOMAIN + canonical(protected)


def binding(facts):
    validate("facts", facts)
    chain, wallet = facts["extId"].split(":")[1:]
    return {
        "chainId": chain,
        "wallet": wallet,
        "identityRef": "0x" + keccak(text=facts["issuerAid"]).hex(),
    }


def check_assessment(a):
    validate("assessment", a)
    core = a["decision"]
    if digest(core) != a["decisionDigest"]:
        raise ValueError("decision digest mismatch")
    if core["reasonCode"] not in REASONS[core["outcome"]]:
        raise ValueError("outcome/reason contradiction")
    if core["outcome"] == "valid" and core["facts"] is None:
        raise ValueError("valid requires facts")


def check_event(event):
    validate("event", event)
    check_assessment(event["assessment"])
    core = {k: v for k, v in event.items() if k != "eventId"}
    if event["eventId"] != digest(core):
        raise ValueError("event digest mismatch")
    if event["assessment"]["decision"]["facts"] is None:
        raise ValueError("events require previously enrolled facts")


def endpoint(method, target):
    said = r"E[A-Za-z0-9_-]{43}"
    if method == "POST" and target == "/v1/verifier-events":
        return "event", "ack", "200"
    if method == "POST" and re.fullmatch(
        r"/v1/assessments/" + said + "/refresh", target
    ):
        return "refreshRequest", "pending", "202"
    if method == "GET" and re.fullmatch(r"/v1/assessments/" + said, target):
        return "empty", "assessment", "200"
    if method == "GET" and re.fullmatch(r"/v1/assessments/" + said + "/facts", target):
        return "empty", "factsResponse", "200"
    if method == "GET" and re.fullmatch(r"/v1/refreshes/[0-9a-f]{64}", target):
        return "empty", "refresh", None
    if method == "GET" and re.fullmatch(
        r"/v1/events\?after=(0|[1-9][0-9]{0,19})&limit=([1-9]|1[0-9]|20)&stream=(initial|[A-Za-z0-9_-]{43})",
        target,
    ):
        return "empty", "replay", "200"
    raise ValueError("noncanonical or unsupported endpoint")


def check_envelope(
    raw,
    *,
    key,
    signer,
    audience,
    establishment,
    method,
    target,
    now,
    skew,
    lifetime,
    request=None,
    status=None,
):
    """Check static envelope claims against explicit fixture trust/request state.

    Does not simulate discovery, durable replay prevention or network refresh.
    """
    env = parse(raw)
    validate("envelope", env)
    p, payload = env["protected"], env["payload"]
    req_shape, response_shape, success_status = endpoint(method, target)
    if (
        p["signerAid"],
        p["audience"],
        p["establishment"],
        p["method"],
        p["target"],
    ) != (signer, audience, establishment, method, target):
        raise ValueError("trust or resource binding mismatch")
    if not signer.startswith(("D", "E")) or not audience.startswith(("D", "E")):
        raise ValueError("service AIDs must be transferable")
    issued, expires = int(p["issuedAt"]), int(p["expiresAt"])
    if not (
        issued <= now + skew
        and now < expires
        and issued < expires
        and expires - issued <= lifetime
    ):
        raise ValueError("expired or invalid lifetime")
    if p["payloadDigest"] != digest(payload):
        raise ValueError("payload digest mismatch")
    signature = Siger(qb64=env["signature"])
    if (
        signature.qb64 != env["signature"]
        or signature.index != 0
        or not Verfer(qb64=key).verify(signature.raw, signing_bytes(p))
    ):
        raise ValueError("bad signature")
    if request is None:
        if (p["kind"], p["requestDigest"], p["requestNonce"], p["status"]) != (
            "request",
            None,
            None,
            None,
        ):
            raise ValueError("request context")
        validate(req_shape, payload)
        if (
            req_shape == "refreshRequest"
            and payload["associationSaid"] != target.split("/")[3]
        ):
            raise ValueError("association/path mismatch")
    else:
        rp = request["protected"]
        if (p["kind"], p["requestDigest"], p["requestNonce"], p["status"]) != (
            "response",
            digest(request),
            rp["nonce"],
            status,
        ):
            raise ValueError("response context")
        if (p["signerAid"], p["audience"]) != (rp["audience"], rp["signerAid"]):
            raise ValueError("response direction")
        if (method, target) != (rp["method"], rp["target"]):
            raise ValueError("response resource")
        if int(status) >= 400:
            validate("error", payload)
        else:
            if response_shape == "refresh":
                response_shape = "pending" if status == "202" else "complete"
                if status not in ("200", "202"):
                    raise ValueError("poll status")
            elif status != success_status:
                raise ValueError("status does not match endpoint")
            validate(response_shape, payload)
    if req_shape == "event" and request is None:
        check_event(payload)
        if payload["assessment"]["verifierAid"] != signer:
            raise ValueError("event authority mismatch")
    if request is not None and int(status) < 400:
        if response_shape == "ack":
            check_ack(payload, request["payload"])
        if response_shape == "assessment":
            check_assessment(payload)
        if response_shape in ("assessment", "factsResponse") and (
            payload["associationSaid"] != target.split("/")[3]
            or payload["verifierAid"] != signer
        ):
            raise ValueError("response identity mismatch")
        if (
            response_shape == "complete"
            and payload["assessment"]["verifierAid"] != signer
        ):
            raise ValueError("refresh authority mismatch")
        if response_shape == "replay":
            after = int(target.split("after=")[1].split("&")[0])
            stream = target.split("stream=")[1]
            check_page(
                payload,
                stream=payload["streamId"] if stream == "initial" else stream,
                after=after,
                verifier=signer,
            )
    return env


def check_ack(ack, event):
    validate("ack", ack)
    if (ack["eventId"], ack["acceptanceId"], ack["payloadDigest"]) != (
        event["eventId"],
        event["eventId"],
        digest(event),
    ):
        raise ValueError("ACK event binding")


def check_revision_floor(request, current):
    validate("refreshRequest", request)
    if int(request["minRevision"]) > current:
        raise ValueError("revision floor ahead of verifier; reconcile rollback")


def consume_nonce(seen, request, *, now, skew):
    """Contract state transition AFTER authentication; real stores come later."""
    p = request["protected"]
    key = (p["signerAid"], p["audience"], p["nonce"])
    if key in seen:
        raise ValueError("request nonce replay")
    if now >= int(p["expiresAt"]):
        raise ValueError("request expired")
    seen[key] = int(p["expiresAt"]) + skew


def security_time(floor, now):
    """Persist the returned floor BEFORE admission or replay-record pruning."""
    if now < floor:
        raise ValueError("security clock rollback; suspend intake")
    return now


def check_page(page, *, stream, after, verifier):
    validate("replay", page)
    if page["streamId"] != stream or int(page["after"]) != after:
        raise ValueError("stream or cursor mismatch")
    position = after
    for event in page["events"]:
        check_event(event)
        if event["assessment"]["verifierAid"] != verifier:
            raise ValueError("replay authority mismatch")
        position += 1
        if event["streamId"] != stream or int(event["eventSequence"]) != position:
            raise ValueError("replay gap or order")
    if int(page["next"]) != position or int(page["highWater"]) < position:
        raise ValueError("cursor regression")
    if not page["events"] and int(page["highWater"]) != after:
        raise ValueError("nonterminal empty page")


def check_refresh(
    result, request, *, now, accepted_at, max_account_age, max_source_age, skew
):
    """Validate use-time claims; returns whether a completed refresh can grant.

    Native evidence and configured peer-set validation remain verifier duties.
    The oracle validates the signed observation summary and request binding.
    """
    validate("complete", result)
    p, requested = request["protected"], request["payload"]
    if (
        result["requestId"],
        result["originRequestDigest"],
        result["originRequestNonce"],
        result["associationSaid"],
        result["expiresAt"],
    ) != (
        digest(request),
        digest(request),
        p["nonce"],
        requested["associationSaid"],
        p["expiresAt"],
    ):
        raise ValueError("refresh origin mismatch")
    if now >= int(result["expiresAt"]):
        raise ValueError("refresh expired")
    a = result["assessment"]
    check_assessment(a)
    if a["associationSaid"] != requested["associationSaid"] or int(a["revision"]) < int(
        requested["minRevision"]
    ):
        raise ValueError("refresh identity or revision mismatch")
    if a["decision"]["outcome"] != "valid":
        return False
    facts = a["decision"]["facts"]
    if binding(facts)["chainId"] != requested["chainId"]:
        raise ValueError("refresh chain mismatch")
    account = a["observations"]["account"]
    if (
        account is None
        or account["chainId"] != requested["chainId"]
        or account["codeClass"] == "contract"
    ):
        raise ValueError("account observation mismatch")
    if (
        account["codeClass"] == "empty"
        and account["codeDigest"] != hashlib.sha256(b"").hexdigest()
    ):
        raise ValueError("empty code digest mismatch")
    observed = int(account["observedAt"])
    if (
        not accepted_at <= observed <= now + skew
        or now - observed > max_account_age
        or observed >= int(result["expiresAt"])
    ):
        raise ValueError("account observation stale")
    credentials = a["observations"]["credentials"]
    expected = {a["associationSaid"], facts["leSaid"], facts["qviSaid"]}
    if len(credentials) != 3 or {c["credentialSaid"] for c in credentials} != expected:
        raise ValueError("source coverage mismatch")
    for c in credentials:
        if c["telSequence"] != "0":
            raise ValueError("valid requires issued source state")
        if c["credentialSaid"] == a["associationSaid"] and (
            c["registrySaid"],
            c["issuerAid"],
            c["telDigest"],
        ) != (
            facts["issuance"]["registrySaid"],
            facts["issuerAid"],
            facts["issuance"]["telDigest"],
        ):
            raise ValueError("association observation/facts mismatch")
        start, end = int(c["startedAt"]), int(c["completedAt"])
        if (
            not accepted_at <= start <= end <= now + skew
            or end >= int(result["expiresAt"])
            or now - end > max_source_age
        ):
            raise ValueError("source observation stale")
        peers = [r["peerAid"] for r in c["peers"]]
        if peers != sorted(set(peers)) or any(
            not start <= int(r["completedAt"]) <= end for r in c["peers"]
        ):
            raise ValueError("peer observation mismatch")
    return True


class Reducer:
    """In-memory decision table for vectors; no durability claim."""

    def __init__(self):
        self.current = {}
        self.history = {}
        self.inbox = {}
        self.positions = {}
        self.invalidations = {}
        self.valid_revisions = {}
        self.terminal = {}
        self.quarantined = set()

    def assessment(self, a):
        check_assessment(a)
        key = (a["verifierAid"], a["associationSaid"])
        revision = int(a["revision"])
        hkey = (*key, revision)
        old = self.current.get(key)
        if hkey in self.history and self.history[hkey] != a["decisionDigest"]:
            self.quarantined.add(key)
            raise ValueError("same revision conflict")
        if old:
            previous = old["decision"]
            facts = a["decision"]["facts"]
            if (
                previous["facts"] is not None
                and previous["facts"] != facts
                and (facts is not None or revision >= int(old["revision"]))
            ):
                self.quarantined.add(key)
                raise ValueError("immutable facts conflict")
        core = a["decision"]
        if (
            key in self.terminal
            and revision > self.terminal[key]
            and core["reasonCode"] not in REVOKED
        ):
            self.quarantined.add(key)
            raise ValueError("terminal revocation")
        # Evidence safety is independent of which revision arrived first.
        if core["reasonCode"] in REVOKED:
            self.terminal[key] = min(revision, self.terminal.get(key, revision))
            self.invalidations[key] = a
            if self.valid_revisions.get(key, 0) > revision:
                self.quarantined.add(key)
                raise ValueError("terminal revocation contradicts later valid history")
        elif core["outcome"] == "valid":
            self.valid_revisions[key] = max(revision, self.valid_revisions.get(key, 0))
            invalid = self.invalidations.get(key)
            if (
                invalid
                and key not in self.terminal
                and revision > int(invalid["revision"])
            ):
                self.invalidations.pop(key)
        elif core["outcome"] == "invalid" and key not in self.terminal:
            invalid = self.invalidations.get(key)
            if revision > self.valid_revisions.get(key, 0) and (
                not invalid or revision > int(invalid["revision"])
            ):
                self.invalidations[key] = a
        self.history[hkey] = a["decisionDigest"]
        if old and revision <= int(old["revision"]):
            return "same" if revision == int(old["revision"]) else "stale"
        self.current[key] = a
        return "applied"

    def event(self, event):
        check_event(event)
        eid = event["eventId"]
        payload_digest = digest(event)
        position = (
            event["assessment"]["verifierAid"],
            event["streamId"],
            event["eventSequence"],
        )
        if position in self.positions and self.positions[position] != eid:
            raise ValueError("stream position conflict")
        if eid in self.inbox:
            prior_digest, ack = self.inbox[eid]
            if prior_digest != payload_digest:
                raise ValueError("same event ID conflict")
            return ack
        outcome = self.assessment(event["assessment"])
        ack = {
            "acceptanceId": eid,
            "eventId": eid,
            "payloadDigest": payload_digest,
            "outcome": outcome,
        }
        self.inbox[eid] = (payload_digest, ack)
        self.positions[position] = eid
        return ack
