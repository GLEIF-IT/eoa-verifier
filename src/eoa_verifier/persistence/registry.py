"""Persist accepted credential revocation identifiers alongside the KERIpy TEL index."""

from keri.core import serdering
from keri.db import dbing, subing
from keri.vdr import viring


class VerifierReger(viring.Reger):
    """Keep revocation records in the same LMDB transaction as the accepted TEL index.

    In pinned KERIpy, Tever.logEvent calls putTel only after validating the TEL
    event and its anchor. Event bytes have already been persisted in tvts. This
    narrow override preserves KERIpy validation and replaces the final index write
    with an atomic index-plus-revocation write. Transient Tever cues are not recovery
    records. Changes to this upstream boundary require requalification.
    """

    def reopen(self, **kwa):
        """Bind the revocation table after opening all KERIpy registry subdatabases."""
        super().reopen(**kwa)
        try:
            self.revocations = subing.Suber(db=self, subkey="verifier-revocations.")
        except Exception:
            self.close()
            raise
        return self.env

    def putTel(self, key, val):
        """Insert an accepted TEL index and, for rev/brv, its exact credential SAID."""
        pre, _ = dbing.splitKeySN(key)
        with self.env.begin(write=True) as txn:
            raw = txn.get(dbing.dgKey(pre, val), db=self.tvts)
            if raw is None:
                raise ValueError("accepted TEL index requires stored event bytes")
            telSerder = serdering.SerderKERI(raw=bytes(raw))
            inserted = txn.put(key, val, db=self.tels, overwrite=False)
            if inserted and telSerder.ilk in ("rev", "brv"):
                txn.put(
                    telSerder.pre.encode(),
                    telSerder.said.encode(),
                    db=self.revocations.sdb,
                )
            return inserted

    def next_revocation(self) -> tuple[str, str] | None:
        """Return one detached (credential SAID, TEL event SAID) revocation record, or None."""
        with self.env.begin(db=self.revocations.sdb) as txn, txn.cursor() as cursor:
            if cursor.first():
                credSaidb, telEvtSaidb = cursor.item()
                credSaid = credSaidb.decode()
                telEvtSaid = telEvtSaidb.decode()
                return credSaid, telEvtSaid
        return None
