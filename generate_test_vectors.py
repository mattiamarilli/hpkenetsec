import random
from cryptography.hazmat.primitives import serialization
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey
import secrets
from cryptography.hazmat.primitives.asymmetric import x25519
import json
import os

# Stampa i valori
KEMIds = [int("0x0010", 16),int("0x0011", 16),int("0x0012", 16),int("0x0020", 16),int("0x0021", 16)]
#KEMIds = [int("0x0020", 16)]
KDFIds = [int("0x0001", 16), int("0x0002", 16), int("0x0003", 16)]
AEADIds = [int("0x0001", 16), int("0x0002", 16), int("0x0003", 16)]
infos =[b"antani",b"prematurata",b"sbiriguda",b"dominus vobiscum blinda"]
aads =[b"Mascetti",b"Melandri",b"Perozzi",b"Necchi"]
pt = [b"MAMBO JUMBO", b"JUMBO MAMBO", b"CONTE LELLO MASCETTI", b"TIKI TAKI", b"TARAPIO TAPIOCO", b"HA CLACSONATO?",
      b"Cippa Lippa!", b"Che cos'e' il genio? E' fantasia intuizione decisione e velocita d'esecuzione."]
directory = "./testvectors/generated/test"


def generate_keys():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Converte le chiavi in formato bytes (serializzazione)
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return private_key_bytes.hex(), public_key_bytes.hex()


for i in range(len(pt)):
    mode = i % 4
    psk = secrets.token_bytes(32).hex()
    psk_id = secrets.token_bytes(16).hex()
    info = random.choice(infos).hex()
    aad = random.choice(aads).hex()
    # kem_id = 32
    # kdf_id = 1
    # aead_id = 1
    kem_id = random.choice(KEMIds)
    kdf_id = random.choice(KDFIds)
    aead_id = random.choice(AEADIds)

    suite_s = CipherSuite.new(
        KEMId(kem_id), KDFId(kdf_id), AEADId(aead_id)
    )

    keypair = suite_s.kem.derive_key_pair(b"test")
    sks, pks = keypair.private_key.to_private_bytes().hex(), keypair.public_key.to_public_bytes().hex()

    keypair = suite_s.kem.derive_key_pair(b"test")
    skr, pkr = keypair.private_key.to_private_bytes().hex(), keypair.public_key.to_public_bytes().hex()

    match mode:
        case 3:
            enc, sender = suite_s.create_sender_context(
                suite_s.kem.deserialize_public_key(bytes.fromhex(pkr)),
                info=bytes.fromhex(info),
                psk=bytes.fromhex(psk),
                psk_id=bytes.fromhex(psk_id),
                sks=suite_s.kem.deserialize_private_key(bytes.fromhex(sks))
            )
        case 2:
            enc, sender = suite_s.create_sender_context(
                suite_s.kem.deserialize_public_key(bytes.fromhex(pkr)),
                info=bytes.fromhex(info),
                sks=suite_s.kem.deserialize_private_key(bytes.fromhex(sks))
            )
        case 1:
            enc, sender = suite_s.create_sender_context(
                suite_s.kem.deserialize_public_key(bytes.fromhex(pkr)),
                info=bytes.fromhex(info),
                psk=bytes.fromhex(psk),
                psk_id=bytes.fromhex(psk_id)
            )
        case 0:
            enc, sender = suite_s.create_sender_context(
                suite_s.kem.deserialize_public_key(bytes.fromhex(pkr)),
                info=bytes.fromhex(info)
            )
    ciphertext = sender.seal(pt[i], aad=bytes.fromhex(aad))

    data = {
        "pt": pt[i].hex(),
        "aad": aad,
    }
    exc_data = {
        "enc": enc.hex(),
        "ct": ciphertext.hex(),
        "aad": aad,
    }

    sender = {
        "info": {
            "psk": psk,
            "psk_id": psk_id,
            "sk": sks
        },
        "pub_data": {
            "mode": mode,
            "kem_id": kem_id,
            "kdf_id": kdf_id,
            "aead_id": aead_id,
            "info": info,
            "pk_s": pks,
            "pk_r": pkr
        }
    }

    receiver = {
        "info": {
            "psk": psk,
            "psk_id": psk_id,
            "sk": skr
        },
        "pub_data": {
            "mode": mode,
            "kem_id": kem_id,
            "kdf_id": kdf_id,
            "aead_id": aead_id,
            "info": info,
            "pk_s": pks,
            "pk_r": pkr
        }
    }

    full_dir_path = f"{directory}{i + 1}"
    if not os.path.exists(full_dir_path):
        os.makedirs(full_dir_path)

    json_data = json.dumps(data, indent=4)

    with open(full_dir_path + "/data.json", "w") as file:
        file.write(json_data)

    json_data = json.dumps(sender, indent=4)

    with open(full_dir_path + "/sender.json", "w") as file:
        file.write(json_data)

    json_data = json.dumps(receiver, indent=4)

    with open(full_dir_path + "/receiver.json", "w") as file:
        file.write(json_data)

    json_data = json.dumps(exc_data, indent=4)

    with open(full_dir_path + "/exc_data.json", "w") as file:
        file.write(json_data)
