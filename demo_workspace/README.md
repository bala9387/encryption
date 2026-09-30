# Demo identities — NOT secret, NOT for real use

Pre-generated ML-KEM-768 / ML-DSA-65 identities (alice, bob, carol) that the
Vercel deployment copies into /tmp on every cold start, so all serverless
instances share the same keys. Their secret keys are protected only by the
public demo passphrase `password123`, which is committed in this repository.

Never encrypt a real document for these identities. For real use, create
identities locally with `python ps26237.py keygen --id NAME`.
