"""Pin the association and its LE/QVI source schemas before native intake."""

from importlib.resources import files

from keri.core import scheming

from .constants import ASSOCIATION_SCHEMA, LE_SCHEMA, QVI_SCHEMA

SCHEMAS = {
    "external-association-v1.json": ASSOCIATION_SCHEMA,
    "legal-entity-vLEI-credential.json": LE_SCHEMA,
    "qualified-vLEI-issuer-vLEI-credential.json": QVI_SCHEMA,
}


def pin_accepted_schemas(hby):
    for name, said in SCHEMAS.items():
        raw = files(__package__).joinpath("schema_data", name).read_bytes()
        schema = scheming.Schemer(raw=raw)
        if schema.said != said:
            raise ValueError(f"packaged schema {name} differs from its pinned SAID")
        hby.db.schema.pin(keys=(said,), val=schema)
