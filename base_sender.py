import hybrid_pke
hybrid_pke.Kem.DHKEM_P521
hpke = hybrid_pke.default()
info = b""  # shared metadata, correspondance-level
aad = b""  # shared metadata, message-level

message = b"MAMBO JUMBO!"
encap, ciphertext = hpke.seal(public_key_r, info, aad, message)