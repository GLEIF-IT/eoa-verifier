"""KERIpy registry with a durable handoff for accepted credential revocations."""

from keri.core import serdering
from keri.db import dbing, subing
from keri.vdr import viring


class VerifierReger(viring.Reger):
    """Keep revocation handoffs in the same LMDB transaction as the accepted TEL index.

    In pinned KERIpy, Tever.logEvent calls putTel only after validating the TEL
    event and its anchor. Event bytes have already been persisted in tvts. This
    narrow override preserves native validation and replaces the final index write
    with an atomic index-plus-handoff write. Transient Tever cues are not recovery
    records. Changes to this upstream boundary require requalification.
    """

    def reopen(self, **kwa):
        """Bind the handoff after opening all native registry subdatabases."""
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
            event = serdering.SerderKERI(raw=bytes(raw))
            inserted = txn.put(key, val, db=self.tels, overwrite=False)
            if inserted and event.ilk in ("rev", "brv"):
                txn.put(
                    event.pre.encode(), event.said.encode(), db=self.revocations.sdb
                )
            return inserted

    def next_revocation(self):
        """Return one detached (credential SAID, TEL event SAID) handoff, or None."""
        with self.env.begin(db=self.revocations.sdb) as txn, txn.cursor() as cursor:
            if cursor.first():
                key, value = cursor.item()
                return key.decode(), value.decode()
        return None
