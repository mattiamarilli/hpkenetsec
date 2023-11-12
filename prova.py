import hybrid_pke
hpke = hybrid_pke.default()
info = b""  # shared metadata, correspondance-level
aad = b""  # shared metadata, message-level
secret_key_r, public_key_r = hpke.generate_key_pair()  # receiver keys, pre-generated

# ============== Sender ==============

message = b"MUMBO JUMBO!"
encap, ciphertext = hpke.seal(public_key_r, info, aad, message)

# ============= Receiver =============

plaintext = hpke.open(encap, secret_key_r, info, aad, ciphertext)
print(plaintext.decode("utf-8"))
# >> hello from the other side!