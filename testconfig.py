import hybrid_pke
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey
import pyca

skr_str = "cb29a95649dc5656c2d054c1aa0d3df0493155e9d5da6d7e344ed8b6a64a9423"
pkr_str = "1d11a3cd247ae48e901939659bd4d79b6b959e1f3e7d66663fbc9412dd4e0976"
suite_s = CipherSuite.new(
    KEMId(32), KDFId(1), AEADId(1)
)


enc, sender = suite_s.create_sender_context(KEMKey.from_pem(pkr))

ct = sender.seal(b"Hello world!")

suite_r = CipherSuite.new(
    KEMId(32), KDFId(1), AEADId(1)
)
recipient = suite_r.create_recipient_context(enc, KEMKey.from_pem(skr))
pt = recipient.open(ct)
