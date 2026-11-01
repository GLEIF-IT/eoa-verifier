"""Native KEL lookup contracts across interactions, rotations and absent events.

These tests exercise actual KERIpy stores and key-state changes. Signature and
TEL validation remain covered by the witnessed IPEX integration flow; this
module checks which historical establishment and witness set they receive.
"""

from unittest.mock import patch

import pytest
from keri import core
from keri.app import habbing
from keri.core import eventing
from keri.db import dbing

from eoa_verifier.receiving.keying import Kevery, est_event


@pytest.fixture
def issuer():
    """Borrow a native issuer with one witness and accepted local KEL entries.

    The witness prefix identifies its key; this lookup-only fixture does not
    transport receipts or assert remote acceptance of locally owned events.
    KERIpy owns the temporary store and removes it when the context closes.
    """
    with habbing.openHby(name="issuer", temp=True) as hby:
        wit = core.Signer(transferable=False).verfer.qb64
        hab = hby.makeHab(name="issuer", wits=[wit], toad=1)
        yield hby, hab


@pytest.mark.parametrize("cold", [False, True])
def test_current_epoch_uses_accepted_index_without_historical_walk(issuer, cold):
    """Interaction history cannot make a current-epoch lookup traverse the KEL."""
    hby, hab = issuer
    inception = hab.kever.serder
    for _ in range(32):
        hab.interact(data=[])
    sn = hab.kever.sn
    if cold:
        # Reload through the persisted accepted-state index, as after restart.
        hby.db.kevers.clear()
    kvy = Kevery(db=hby.db)
    with (
        patch.object(
            eventing.Kevery,
            "fetchEstEvent",
            side_effect=AssertionError("unexpected historical establishment walk"),
        ),
        patch.object(
            eventing.Kevery,
            "fetchWitnessState",
            side_effect=AssertionError("unexpected historical witness walk"),
        ),
    ):
        assert kvy.fetchEstEvent(hab.pre, sn).said == inception.said
        assert est_event(hby.kvy, hab.pre, sn).said == inception.said
        assert [wit.qb64 for wit in kvy.fetchWitnessState(hab.pre, sn)] == (
            inception.backs
        )


def test_rotation_keeps_older_anchors_bound_to_older_witnesses(issuer):
    """Today's establishment cannot replace the key/witness authority of an old anchor."""
    hby, hab = issuer
    inception = hab.kever.serder
    hab.interact(data=[])
    old_sn = hab.kever.sn
    old_wit = hab.kever.wits[0]
    new_wit = core.Signer(transferable=False).verfer.qb64
    hab.rotate(cuts=[old_wit], adds=[new_wit], toad=1)
    rotation = hab.kever.serder
    hab.interact(data=[])
    kvy = Kevery(db=hby.db)
    assert kvy.fetchEstEvent(hab.pre, old_sn).said == inception.said
    assert est_event(hby.kvy, hab.pre, old_sn).said == inception.said
    assert [wit.qb64 for wit in kvy.fetchWitnessState(hab.pre, old_sn)] == [old_wit]
    assert kvy.fetchEstEvent(hab.pre, hab.kever.sn).said == rotation.said
    assert [wit.qb64 for wit in kvy.fetchWitnessState(hab.pre, hab.kever.sn)] == [
        new_wit
    ]


def test_unknown_and_future_events_keep_native_lookup_behavior(issuer):
    """Cached state cannot establish acceptance of an unknown identifier or future event."""
    hby, hab = issuer
    hab.interact(data=[])
    native = eventing.Kevery(db=hby.db)
    kvy = Kevery(db=hby.db)
    unknown = core.Signer().verfer.qb64
    for pre, sn in ((unknown, 0), (hab.pre, hab.kever.sn + 1)):
        assert kvy.fetchEstEvent(pre, sn) is None
        assert est_event(hby.kvy, pre, sn) is None
        assert [wit.qb64 for wit in kvy.fetchWitnessState(pre, sn)] == [
            wit.qb64 for wit in native.fetchWitnessState(pre, sn)
        ]


def test_missing_accepted_entry_is_not_inferred_from_head_state(issuer):
    """A head beyond a missing KEL slot is insufficient to return an establishment."""
    hby, hab = issuer
    for _ in range(4):
        hab.interact(data=[])
    hby.db.delKes(dbing.snKey(hab.pre, 2))
    kvy = Kevery(db=hby.db)
    native = eventing.Kevery(db=hby.db)
    assert kvy.fetchEstEvent(hab.pre, 2) is None
    assert est_event(hby.kvy, hab.pre, 2) is None
    assert [wit.qb64 for wit in kvy.fetchWitnessState(hab.pre, 2)] == [
        wit.qb64 for wit in native.fetchWitnessState(hab.pre, 2)
    ]


def test_missing_event_bytes_are_not_inferred_from_the_accepted_index(issuer):
    """An ordinal index entry without its event cannot satisfy an event lookup."""
    hby, hab = issuer
    hab.interact(data=[])
    sn, said = hab.kever.sn, hab.kever.serder.said
    hby.db.delEvt(dbing.dgKey(hab.pre, said))
    assert hby.db.getKeLast(dbing.snKey(hab.pre, sn)) is not None
    assert eventing.Kevery(db=hby.db).fetchEstEvent(hab.pre, sn) is None
    assert Kevery(db=hby.db).fetchEstEvent(hab.pre, sn) is None
    assert est_event(hby.kvy, hab.pre, sn) is None
