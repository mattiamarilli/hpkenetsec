import hybrid_pke
hybrid_pke.Kem.DHKEM_P521
hpke = hybrid_pke.default()
info = b""  # shared metadata, correspondance-level
aad = b""  # shared metadata, message-level

secret_key_r, public_key_r = hpke.generate_key_pair()  # receiver keys, pre-generated

plaintext = hpke.open(encap, secret_key_r, info, aad, ciphertext)
print(plaintext.decode("utf-8"))