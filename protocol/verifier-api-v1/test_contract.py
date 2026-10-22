"""Known-answer and adversarial contract tests, with no optional skips."""

import base64
import hashlib
import json
import unittest
from copy import deepcopy

from conformance import (
    ROOT,
    SCHEMA,
    Reducer,
    binding,
    canonical,
    check_ack,
    check_assessment,
    check_envelope,
    check_page,
    check_refresh,
    check_revision_floor,
    consume_nonce,
    digest,
    endpoint,
    parse,
    security_time,
    signing_bytes,
)
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak
from jsonschema import Draft202012Validator, ValidationError
from keri.core import Siger, Signer, Verfer, serdering

V = json.loads((ROOT / "vectors.json").read_text())
E = {n: v["envelope"] for n, v in V["envelopes"].items()}
ERRORS = (ValueError, ValidationError)


def context(name):
    env = E[name]
    p = env["protected"]
    peer = V["verifier"] if p["signerAid"] == V["verifier"]["aid"] else V["oracle"]
    epoch = int(p["establishment"]["sequence"])
    request = None
    if p["kind"] == "response":
        request = next(e for e in E.values() if digest(e) == p["requestDigest"])
    return {
        "key": peer["keys"][epoch],
        "signer": peer["aid"],
        "audience": p["audience"],
        "establishment": p["establishment"],
        "method": p["method"],
        "target": p["target"],
        "now": 1800000005,
        "skew": 1,
        "lifetime": 30,
        "request": request,
        "status": p["status"],
    }


def resign(env, source):
    # Test attacker controls an authorized test key; semantic checks must still fail.
    original = E[source]["protected"]
    who = (
        V["verifier"] if original["signerAid"] == V["verifier"]["aid"] else V["oracle"]
    )
    key = Signer(
        raw=bytes.fromhex(
            who["publicTestSeeds"][int(original["establishment"]["sequence"])]
        )
    )
    env["protected"]["payloadDigest"] = digest(env["payload"])
    env["signature"] = key.sign(signing_bytes(env["protected"]), index=0).qb64


class WireContract(unittest.TestCase):
    def test_all_shapes_and_exact_signing_vectors(self):
        Draft202012Validator.check_schema(SCHEMA)
        for name, item in V["envelopes"].items():
            with self.subTest(name=name):
                env = item["envelope"]
                self.assertEqual(
                    signing_bytes(env["protected"]).hex(), item["signingHex"]
                )
                self.assertEqual(digest(env), item["wireSha256"])
                self.assertEqual(check_envelope(canonical(env), **context(name)), env)

    def test_public_keys_sign_native_establishment_events(self):
        for who in (V["verifier"], V["oracle"]):
            for epoch, name in enumerate(("inception", "rotation")):
                # KERI event serialization uses native ordering, not API canonical JSON.
                event = serdering.SerderKERI(sad=who[name])
                self.assertEqual(event.pre, who["aid"])
                self.assertEqual(event.sn, epoch)
                self.assertEqual(event.ked["kt"], "1")
                self.assertEqual(len(event.ked["k"]), 1)
                sig = Siger(qb64=who[name + "Signature"])
                self.assertTrue(
                    Verfer(qb64=who["keys"][epoch]).verify(sig.raw, event.raw)
                )
            self.assertEqual(who["rotation"]["p"], who["inception"]["d"])

    def test_rotated_message_rejects_old_accepted_epoch_and_wrong_key(self):
        old = context("event")
        with self.assertRaises(ValueError):
            check_envelope(canonical(E["rotatedEvent"]), **old)
        newer = context("rotatedEvent")
        with self.assertRaises(ValueError):
            check_envelope(canonical(E["event"]), **newer)
        with self.assertRaises(ValueError):
            check_envelope(
                canonical(E["event"]), **(old | {"key": V["oracle"]["keys"][0]})
            )

    def test_negative_wire_vectors(self):
        for case in json.loads((ROOT / "negative-vectors.json").read_text()):
            with self.subTest(name=case["name"]):
                altered = deepcopy(E[case["source"]])
                node = altered
                for part in case["path"][:-1]:
                    node = node[part]
                node[case["path"][-1]] = case["value"]
                if case["resign"]:
                    resign(altered, case["source"])
                with self.assertRaises(ERRORS):
                    check_envelope(canonical(altered), **context(case["source"]))

    def test_noncanonical_json_and_body_bounds(self):
        for raw in [
            b'{"x":"a","x":"b"}',
            b'{ "x":"a"}',
            b'{"x":"a"}\n',
            b'{"x":1}',
            b'{"x":1.0}',
            b'{"x":NaN}',
            b'{"x":"\\u0061"}',
            b'{"x":"\\/"}',
            b'{"x":"\\n"}',
            b"\xef\xbb\xbf{}",
            b'{"x":"\xc3\xa9"}',
            b" " * 1_048_577,
        ]:
            with self.subTest(raw=raw[:40]), self.assertRaises(ValueError):
                parse(raw)
        self.assertEqual(
            canonical({"z": True, "a": [None, 'quote"slash/back\\']}),
            b'{"a":[null,"quote\\"slash/back\\\\"],"z":true}',
        )

    def test_get_authorization_is_exact_unpadded_base64url(self):
        raw = canonical(E["assessmentQuery"])
        header = base64.urlsafe_b64encode(raw).rstrip(b"=")
        self.assertLess(len(header), 8192)
        self.assertEqual(
            base64.urlsafe_b64decode(header + b"=" * (-len(header) % 4)), raw
        )
        self.assertEqual(E["assessmentQuery"]["payload"], {})

    def test_replayed_request_rejected_but_resigned_event_retry_allowed(self):
        seen = {}
        consume_nonce(seen, E["event"], now=1800000005, skew=1)
        with self.assertRaisesRegex(ValueError, "replay"):
            consume_nonce(seen, E["event"], now=1800000005, skew=1)
        retry = E["rotatedEvent"]
        self.assertEqual(retry["payload"], E["event"]["payload"])
        consume_nonce(seen, retry, now=1800000005, skew=1)
        self.assertEqual(set(seen.values()), {1800000031})

    def test_pruning_time_floor_survives_restart_and_rejects_rollback(self):
        seen = {}
        floor = security_time(0, 1800000005)
        consume_nonce(seen, E["event"], now=floor, skew=1)
        floor = security_time(floor, 1800000040)
        seen = {k: v for k, v in seen.items() if v >= floor}
        self.assertEqual(seen, {})
        # This serialization models retained state, not an LMDB crash test.
        reopened = json.loads(json.dumps({"securityTimeFloor": floor}))
        with self.assertRaisesRegex(ValueError, "rollback"):
            security_time(reopened["securityTimeFloor"], 1800000006)
        now = security_time(reopened["securityTimeFloor"], 1800000041)
        with self.assertRaisesRegex(ValueError, "expired"):
            consume_nonce(seen, E["event"], now=now, skew=1)

    def test_endpoint_aliases_rejected(self):
        for path in [
            "/v1/verifier-events/",
            "/v1/%76erifier-events",
            "/v1/../v1/verifier-events",
            "/v1/events?limit=20&after=0&stream=initial",
            "/v1/events?after=00&limit=20&stream=initial",
            "/v1/events?after=0&limit=21&stream=initial",
            "/v1/events?after=0&limit=20&stream=initial&after=0",
        ]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                endpoint("GET" if "?" in path else "POST", path)

    def test_binding_matches_existing_eip712_carrier(self):
        old = json.loads((ROOT / "carrier/test-vector.json").read_text())
        association = serdering.SerderACDC(
            raw=(ROOT / "carrier/association.json").read_bytes()
        )
        self.assertEqual(association.said, old["associationSaid"])
        signable = encode_typed_data(full_message=old["typedData"])
        self.assertEqual("0x" + signable.header.hex(), old["domainSeparator"])
        self.assertEqual("0x" + signable.body.hex(), old["messageHash"])
        self.assertEqual(
            "0x"
            + keccak(
                b"\x19" + signable.version + signable.header + signable.body
            ).hex(),
            old["signingDigest"],
        )
        self.assertEqual(
            Account.recover_message(signable, signature=old["signature"]), old["signer"]
        )
        facts = V["events"][0]["assessment"]["decision"]["facts"]
        self.assertEqual(binding(facts), V["binding"])
        self.assertEqual(V["binding"]["wallet"], old["signer"].lower())
        self.assertNotEqual(
            V["binding"]["identityRef"],
            "0x" + hashlib.sha3_256(facts["issuerAid"].encode()).hexdigest(),
        )

    def test_copied_carrier_has_pinned_provenance(self):
        provenance = json.loads((ROOT / "provenance.json").read_text())
        self.assertEqual(
            provenance["revision"], "77849caae048381aee96b42f75053368d8d24c53"
        )
        for name, source in provenance["files"].items():
            self.assertEqual(
                hashlib.sha256((ROOT / "carrier" / name).read_bytes()).hexdigest(),
                source["sha256"],
            )


class DecisionContract(unittest.TestCase):
    def test_out_of_order_and_duplicate_traces(self):
        for trace in V["reducerTraces"]:
            reducer = Reducer()
            outcomes = [
                reducer.event(V["events"][int(n) - 1])["outcome"]
                for n in trace["events"]
            ]
            self.assertEqual(outcomes, trace["outcomes"])
            self.assertEqual(
                next(iter(reducer.current.values()))["revision"], trace["finalRevision"]
            )

    def test_same_revision_new_observation_is_not_conflict(self):
        reducer = Reducer()
        a = deepcopy(V["events"][0]["assessment"])
        self.assertEqual(reducer.assessment(a), "applied")
        a["observations"]["account"]["blockNumber"] = "101"
        a["observations"]["account"]["blockHash"] = "0x" + "bc" * 32
        a["observations"]["account"]["observedAt"] = "1800000004"
        self.assertEqual(reducer.assessment(a), "same")

    def test_same_revision_conflict_after_higher_revision(self):
        reducer = Reducer()
        reducer.event(V["events"][0])
        reducer.event(V["events"][3])
        a = deepcopy(V["events"][0]["assessment"])
        a["decision"]["reasonCode"] = "PROOF_INVALID"
        a["decision"]["outcome"] = "invalid"
        a["decisionDigest"] = digest(a["decision"])
        with self.assertRaisesRegex(ValueError, "same revision"):
            reducer.assessment(a)

    def test_revocation_terminal_but_account_invalidity_recovers(self):
        reducer = Reducer()
        for event in V["events"]:
            self.assertEqual(reducer.event(event)["outcome"], "applied")
        for outcome, reason in [("valid", "VALID"), ("unavailable", "RPC_UNAVAILABLE")]:
            a = deepcopy(V["events"][3]["assessment"])
            a["revision"] = "5"
            a["decision"].update(outcome=outcome, reasonCode=reason)
            a["decisionDigest"] = digest(a["decision"])
            with self.assertRaisesRegex(ValueError, "terminal"):
                reducer.assessment(a)

    def test_immutable_facts_and_event_id(self):
        reducer = Reducer()
        event = deepcopy(V["events"][0])
        reducer.event(event)
        event["assessment"]["observations"]["account"]["blockNumber"] = "101"
        with self.assertRaisesRegex(ValueError, "event digest"):
            reducer.event(event)
        a = deepcopy(V["events"][2]["assessment"])
        a["decision"]["facts"]["issuance"]["anchorSequence"] = "13"
        a["decisionDigest"] = digest(a["decision"])
        with self.assertRaisesRegex(ValueError, "immutable facts"):
            reducer.assessment(a)

    def test_exact_ack_and_wrong_ack(self):
        event = V["events"][0]
        ack = E["ack"]["payload"]
        check_ack(ack, event)
        for key in ("eventId", "acceptanceId", "payloadDigest"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                check_ack(ack | {key: "0" * 64}, event)

    def test_replay_requires_contiguous_progress(self):
        page = E["replay"]["payload"]
        check_page(
            page, stream=page["streamId"], after=0, verifier=V["verifier"]["aid"]
        )
        for change in [
            {"events": page["events"][1:]},
            {"events": list(reversed(page["events"]))},
            {"next": "5"},
            {"highWater": "2"},
            {"events": [], "next": "0"},
        ]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                check_page(
                    page | change,
                    stream=page["streamId"],
                    after=0,
                    verifier=V["verifier"]["aid"],
                )
        with self.assertRaises(ValueError):
            check_page(page, stream="A" * 43, after=0, verifier=V["verifier"]["aid"])

    def test_query_decision_cannot_be_overwritten_by_old_webhook(self):
        reducer = Reducer()
        self.assertEqual(reducer.assessment(V["events"][3]["assessment"]), "applied")
        self.assertEqual(reducer.event(V["events"][0])["outcome"], "stale")
        self.assertEqual(next(iter(reducer.current.values()))["revision"], "4")

    def test_signed_replay_cannot_introduce_another_authority(self):
        env = deepcopy(E["replay"])
        for event in env["payload"]["events"]:
            event["assessment"]["verifierAid"] = V["oracle"]["aid"]
            event["eventId"] = digest(
                {k: v for k, v in event.items() if k != "eventId"}
            )
        resign(env, "replay")
        with self.assertRaisesRegex(ValueError, "authority"):
            check_envelope(canonical(env), **context("replay"))

    def test_webhook_and_replay_cannot_disagree_at_same_position(self):
        reducer = Reducer()
        reducer.event(V["events"][0])
        conflicting = deepcopy(V["events"][1])
        conflicting["eventSequence"] = "1"
        conflicting["eventId"] = digest(
            {k: v for k, v in conflicting.items() if k != "eventId"}
        )
        with self.assertRaisesRegex(ValueError, "stream position"):
            reducer.event(conflicting)
        self.assertEqual(next(iter(reducer.current.values()))["revision"], "1")

    def test_invalid_reason_and_missing_facts_cannot_be_valid(self):
        for change in [{"reasonCode": "SOURCE_REVOKED"}, {"facts": None}]:
            a = deepcopy(V["events"][0]["assessment"])
            a["decision"].update(change)
            a["decisionDigest"] = digest(a["decision"])
            with self.assertRaises(ValueError):
                check_assessment(a)

    def test_unavailable_keeps_invalidation_until_account_recovery(self):
        reducer = Reducer()
        reducer.event(V["events"][1])
        a = deepcopy(V["events"][2]["assessment"])
        a["decision"].update(outcome="unavailable", reasonCode="RPC_UNAVAILABLE")
        a["decisionDigest"] = digest(a["decision"])
        reducer.assessment(a)
        self.assertEqual(next(iter(reducer.invalidations.values()))["revision"], "2")
        recovery = deepcopy(V["events"][2]["assessment"])
        recovery["revision"] = "4"
        reducer.assessment(recovery)
        self.assertEqual(reducer.invalidations, {})

    def test_late_invalidation_survives_newer_unavailability(self):
        reducer = Reducer()
        a = deepcopy(V["events"][2]["assessment"])
        a["decision"].update(outcome="unavailable", reasonCode="RPC_UNAVAILABLE")
        a["decisionDigest"] = digest(a["decision"])
        reducer.assessment(a)
        self.assertEqual(reducer.event(V["events"][1])["outcome"], "stale")
        self.assertEqual(next(iter(reducer.invalidations.values()))["revision"], "2")

    def test_late_terminal_revocation_quarantines_contradictory_valid_history(self):
        reducer = Reducer()
        reducer.assessment(V["events"][2]["assessment"])
        a = deepcopy(V["events"][1]["assessment"])
        a["decision"]["reasonCode"] = "ASSOCIATION_REVOKED"
        a["decisionDigest"] = digest(a["decision"])
        with self.assertRaisesRegex(ValueError, "terminal revocation"):
            reducer.assessment(a)
        self.assertTrue(reducer.quarantined)
        self.assertEqual(
            next(iter(reducer.invalidations.values()))["decision"]["reasonCode"],
            "ASSOCIATION_REVOKED",
        )

    def test_late_account_invalidation_does_not_undo_later_valid_recovery(self):
        reducer = Reducer()
        reducer.assessment(V["events"][2]["assessment"])
        self.assertEqual(reducer.event(V["events"][1])["outcome"], "stale")
        self.assertEqual(reducer.invalidations, {})


class FreshnessContract(unittest.TestCase):
    def check(self, result, **overrides):
        args = {
            "now": 1800000005,
            "accepted_at": 1800000001,
            "max_account_age": 5,
            "max_source_age": 5,
            "skew": 1,
        }
        args.update(overrides)
        return check_refresh(result, E["refreshRequest"], **args)

    def test_complete_refresh_and_use_time_aging(self):
        result = E["refreshComplete"]["payload"]
        self.assertTrue(self.check(result))
        with self.assertRaisesRegex(ValueError, "stale"):
            self.check(result, now=1800000010)
        with self.assertRaisesRegex(ValueError, "expired"):
            self.check(result, now=1800000030)

    def test_revision_floor_below_equal_and_above_current(self):
        request = E["refreshRequest"]["payload"]
        check_revision_floor(request | {"minRevision": "0"}, 1)
        check_revision_floor(request, 1)
        with self.assertRaisesRegex(ValueError, "rollback"):
            check_revision_floor(request | {"minRevision": "2"}, 1)

    def test_refresh_rejects_wrong_origin_and_cached_sources(self):
        for key, value in [
            ("originRequestNonce", "A" * 43),
            ("originRequestDigest", "0" * 64),
            ("requestId", "0" * 64),
        ]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check(E["refreshComplete"]["payload"] | {key: value})
        result = deepcopy(E["refreshComplete"]["payload"])
        result["assessment"]["observations"]["credentials"][0]["startedAt"] = (
            "1799999999"
        )
        with self.assertRaisesRegex(ValueError, "source observation"):
            self.check(result)

    def test_refresh_rejects_missing_duplicate_and_wrong_chain_observations(self):
        for mutation in ("missing", "duplicate", "chain", "future", "contract"):
            result = deepcopy(E["refreshComplete"]["payload"])
            obs = result["assessment"]["observations"]
            if mutation == "missing":
                obs["credentials"].pop()
            elif mutation == "duplicate":
                obs["credentials"][1] = deepcopy(obs["credentials"][0])
            elif mutation == "chain":
                obs["account"]["chainId"] = "2"
            elif mutation == "future":
                obs["account"]["observedAt"] = "1800000020"
            else:
                obs["account"]["codeClass"] = "contract"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.check(result)

    def test_unavailable_never_grants(self):
        result = deepcopy(E["refreshComplete"]["payload"])
        a = result["assessment"]
        a["decision"].update(outcome="unavailable", reasonCode="RPC_UNAVAILABLE")
        a["decisionDigest"] = digest(a["decision"])
        a["observations"] = {"account": None, "credentials": []}
        self.assertFalse(self.check(result))

    def test_valid_summary_cannot_contradict_issuance_facts(self):
        for key, value in [
            ("telSequence", "1"),
            ("registrySaid", V["oracle"]["aid"]),
            ("issuerAid", V["oracle"]["aid"]),
            ("telDigest", V["oracle"]["aid"]),
        ]:
            result = deepcopy(E["refreshComplete"]["payload"])
            result["assessment"]["observations"]["credentials"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check(result)


if __name__ == "__main__":
    unittest.main()
