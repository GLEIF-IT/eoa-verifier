"""Compose actual feature services and own isolated KERIpy/application store lifetimes.

verifier_service lends an unscheduled runtime; entered_service enters HIO tasks
without advancing time. Callers retain that distinction when driving tests.
"""

from contextlib import contextmanager

from hio.base import doing
from keri.app import habbing

from eoa_verifier.persistence.associations import AssociationReader
from eoa_verifier.persistence.delivery import DeliveryReader, DeliveryWriter
from eoa_verifier.persistence.verification import VerificationReader, VerificationWriter


@contextmanager
def verifier_service(config):
    """Yield a service borrowing KERIpy stores owned by this fixture.

    The caller must stop its HIO scheduler before leaving this context. Use
    entered_service to enter and exit HIO tasks without advancing scheduler turns. Persistent
    configs retain files for reopening assertions; temporary configs remove them.
    """
    from keri.app import configing, keeping, notifying
    from keri.db import basing, dbing
    from keri.vdr import credentialing

    from eoa_verifier.persistence.basing import VerifierBaser
    from eoa_verifier.persistence.registry import VerifierReger
    from eoa_verifier.runtime.serving import VerifierService

    options = dict(name=config.name, base=config.base, headDirPath=config.head_dir)
    with (
        keeping.openKS(temp=config.temp, **options) as ks,
        basing.openDB(temp=config.temp, **options) as db,
        configing.openCF(temp=config.temp, **options) as cf,
        dbing.openLMDB(cls=VerifierReger, temp=config.temp, db=db, **options) as reger,
        dbing.openLMDB(cls=VerifierBaser, temp=config.temp, **options) as baser,
        dbing.openLMDB(cls=notifying.Noter, temp=config.temp, **options) as noter,
    ):
        hby = habbing.Habery(
            name=config.name,
            base=config.base,
            temp=config.temp,
            ks=ks,
            db=db,
            cf=cf,
            bran=config.passcode,
            free=False,
        )
        rgy = credentialing.Regery(
            hby=hby, name=config.name, base=config.base, temp=config.temp, reger=reger
        )
        service = VerifierService(config, hby=hby, rgy=rgy, baser=baser, noter=noter)
        yield service


@contextmanager
def entered_service(config):
    """Yield an entered service, then stop its tasks before closing borrowed stores.

    This fixture does not advance the scheduler. Tests call the relevant boundary
    directly or supply their own scheduling loop when they need task progress.
    """
    with verifier_service(config) as runtime:
        scheduler = doing.Doist(doers=[runtime])
        try:
            scheduler.enter()
            yield runtime
        finally:
            scheduler.exit()


def verification_service(baser, rgy=None, **options):
    """Compose the production phase service over a test-owned application store."""

    from eoa_verifier.verification.evidence import CredentialEvidence
    from eoa_verifier.verification.verifying import VerificationService

    return VerificationService(
        VerificationReader(baser),
        VerificationWriter(baser),
        CredentialEvidence(rgy),
        **options,
    )


def delivery_service(baser):
    """Compose offline delivery operations without KERIpy keys or HTTP tasks."""
    from eoa_verifier.delivery.delivering import DeliveryService

    return DeliveryService(
        DeliveryReader(baser),
        DeliveryWriter(baser),
        association_reader=AssociationReader(baser),
    )
