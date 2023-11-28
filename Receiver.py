import socket
import json
from pyhpke import AEADId, CipherSuite, KDFId, KEMId
import os


class Receiver:
    def __init__(self, config, ip, port):
        self.mode = config["pub_data"]["mode"]
        self.kem_id = config["pub_data"]["kem_id"]
        self.kdf_id = config["pub_data"]["kdf_id"]
        self.aead_id = config["pub_data"]["aead_id"]
        self.public_key_s = bytes.fromhex(config["pub_data"]["pk_s"])
        self.public_key_r = bytes.fromhex(config["pub_data"]["pk_r"])
        self.private_key_r = bytes.fromhex(config["info"]["sk"])
        self.info = bytes.fromhex(config["pub_data"]["info"])
        self.psk = bytes.fromhex(config["info"]["psk"])
        self.psk_id = bytes.fromhex(config["info"]["psk_id"])
        self.ip = ip
        self.port = port
        self.sock = socket.socket(socket.AF_INET,  # Internet
                                  socket.SOCK_DGRAM)  # UDP
        self.sock.bind((ip, port))

    def listen(self, data_json):
        while True:
            print("Receiver waiting...")
            data, addr = self.sock.recvfrom(1024)  # buffer size is 1024 bytes
            if data == b"key_req":
                self.sock.sendto(self.public_key_s, addr)
                print("Sended public-key to client: %s" % data)
            else:
                decodeddata = json.loads(data)
                suite_r = CipherSuite.new(
                    KEMId(int(self.kem_id)), KDFId(int(self.kdf_id)), AEADId(int(self.aead_id))
                )

                match self.mode:
                    case 3:
                        recipient = suite_r.create_recipient_context(
                            bytes.fromhex(decodeddata["encap"]),
                            suite_r.kem.deserialize_private_key(self.private_key_r),
                            info=self.info,
                            psk=self.psk,
                            psk_id=self.psk_id,
                            pks=suite_r.kem.deserialize_public_key(self.public_key_s)
                        )
                    case 2:
                        recipient = suite_r.create_recipient_context(
                            bytes.fromhex(decodeddata["encap"]),
                            suite_r.kem.deserialize_private_key(self.private_key_r),
                            info=self.info,
                            pks=suite_r.kem.deserialize_public_key(self.public_key_s)
                        )
                    case 1:
                        recipient = suite_r.create_recipient_context(
                            bytes.fromhex(decodeddata["encap"]),
                            suite_r.kem.deserialize_private_key(self.private_key_r),
                            info=self.info,
                            psk=self.psk,
                            psk_id=self.psk_id
                        )
                    case 0:
                        recipient = suite_r.create_recipient_context(
                            bytes.fromhex(decodeddata["encap"]),
                            suite_r.kem.deserialize_private_key(self.private_key_r),
                            info=self.info
                        )

                pt = recipient.open(bytes.fromhex(decodeddata["ciphertext"]), aad=bytes.fromhex(data_json["aad"]))

                print(pt.decode("utf-8"),
                      '\u2705' if pt == bytes.fromhex(data_json["pt"]) else '\U0000274C')
                self.sock.close()
                break

#
# stringa_input = 0
# while int(stringa_input) not in range(1, 5):
#     stringa_input = input("Scegli quale test eseguire (1-4): ")
for i in range(1,sum([len(d) for r, d, f in os.walk('./testvectors/generated')]) + 1):
    base_path = f'./testvectors/generated/test{i}/'
    receiver_json = json.load(open(base_path + 'receiver.json'))
    data_json = json.load(open(base_path + 'data.json'))
    print(f"Test vector {i}")
    receiver = Receiver(receiver_json, "127.0.0.1", 5006)
    receiver.listen(data_json)
