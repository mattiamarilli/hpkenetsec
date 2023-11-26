import hybrid_pke
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey

skr_str = "cb29a95649dc5656c2d054c1aa0d3df0493155e9d5da6d7e344ed8b6a64a9423"
pkr_str = "1d11a3cd247ae48e901939659bd4d79b6b959e1f3e7d66663fbc9412dd4e0976"
suite_s = CipherSuite.new(
    KEMId(32), KDFId(1), AEADId(1)
)

pkr = suite_s.kem.deserialize_public_key(bytes.fromhex(pkr_str))

enc, sender = suite_s.create_sender_context(suite_s.kem.deserialize_public_key(bytes.fromhex(pkr_str)))

ct = sender.seal(b"Hello world!")

suite_r = CipherSuite.new(
    KEMId(32), KDFId(1), AEADId(1)
)
recipient = suite_r.create_recipient_context(enc, suite_r.kem.deserialize_private_key(bytes.fromhex(skr_str)))
pt = recipient.open(ct)

print(pt)