"""Pinned credential schema policy for the GLEIF-rooted association chain.

These content-addressed IDs identify packaged schemas, not verifier result objects.
Upstream revisions and provenance are linked in the repository README.
"""

# GEDA-issued QVI credential: identifies the authorized QVI holder.
QVI_SCHEMA = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
# QVI-issued LE credential: identifies the holder allowed to issue associations.
LE_SCHEMA = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"
# External-association v1 with the 1–128 ASCII nonce contract.
ASSOCIATION_SCHEMA = "ECg_trM84AAnW4ZILy8XhIrXCVSQYqpQ-hktJdk_x0g8"
