"""Read accepted KERI key state without repeatedly traversing current epochs.

KERIpy owns validation and the accepted state index. Its latest establishment
governs accepted interactions at or after that establishment. Earlier anchors
still use KERIpy's historical traversal. This reader adds no persistent cache,
invalidation policy, or alternate signature-validation rules.
"""

from keri.core import eventing, serdering
from keri.db import dbing


def _current_est(kvy, pre, sn):
    """Return the indexed establishment governing accepted ``pre``/``sn``, if any.

    kvy borrows KERIpy's accepted Kevers and database. Both sequence bounds and
    the exact accepted KEL entry are required: a current key-state record alone
    does not establish acceptance of a future or missing event.
    """
    try:
        kever = kvy.kevers[pre]
    except KeyError:
        return None
    lastEst = kever.lastEst
    if not lastEst.s <= sn <= kever.sn:
        return None
    eventDig = kvy.db.getKeLast(dbing.snKey(pre, sn))
    if eventDig is None:
        return None
    if kvy.db.getEvt(dbing.dgKey(pre, bytes(eventDig))) is None:
        return None
    estRaw = kvy.db.getEvt(dbing.dgKey(pre, lastEst.d))
    return serdering.SerderKERI(raw=bytes(estRaw)) if estRaw is not None else None


def est_event(kvy, pre, sn):
    """Return the establishment authoritative for one accepted issuer event.

    Use the accepted index within the current epoch; preserve KERIpy's historical
    lookup and missing-event behavior for every other sequence number. The
    explicit base-class call also lets the parser below share this reader.
    kvy is a borrowed Kevery, pre is the issuer's qb64 AID string, and sn is an
    integer KEL sequence number. Return a SerderKERI or None when unavailable.
    """
    est = _current_est(kvy, pre, sn)
    return est if est is not None else eventing.Kevery.fetchEstEvent(kvy, pre, sn)


class Kevery(eventing.Kevery):
    """Keep native KERI validation with indexed reads inside the current epoch.

    Constructor, acceptance, escrow and signature behavior belong to KERIpy.
    Only its public establishment/witness lookup methods are specialized.
    """

    def fetchEstEvent(self, pre, sn):
        """Return the accepted event's authoritative establishment Serder or None."""
        return est_event(self, pre, sn)

    def fetchWitnessState(self, pre, sn):
        """Return historical witness Prefixers, using the accepted index where authoritative.

        Preserve the native traversal outside an accepted current-epoch event,
        including its behavior for future sequence numbers and missing entries.
        """
        est = _current_est(self, pre, sn)
        if est is not None:
            return self.db.wits.get(dbing.dgKey(pre, est.said))
        return super().fetchWitnessState(pre, sn)
