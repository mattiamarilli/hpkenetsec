import socket
import json
from pyhpke import AEADId, CipherSuite, KDFId, KEMId
import time
import os


class Sender:
    def __init__(self, config, ip, port, ip_recv, port_recv):
        self.mode = config["pub_data"]["mode"]
        self.kem_id = config["pub_data"]["kem_id"]
        self.kdf_id = config["pub_data"]["kdf_id"]
        self.aead_id = config["pub_data"]["aead_id"]
        self.public_key_s = bytes.fromhex(config["pub_data"]["pk_s"])
        self.public_key_r = bytes.fromhex(config["pub_data"]["pk_r"])
        self.private_key_s = bytes.fromhex(config["info"]["sk"])
        self.info = bytes.fromhex(config["pub_data"]["info"])
        self.psk = bytes.fromhex(config["info"]["psk"])
        self.psk_id = bytes.fromhex(config["info"]["psk_id"])
        self.ip = ip
        self.port = port
        self.sock = socket.socket(socket.AF_INET,  # Internet
                                  socket.SOCK_DGRAM)  # UDP
        self.sock.bind((ip, port))
        self.suite_s = CipherSuite.new(
            KEMId(int(self.kem_id)), KDFId(int(self.kdf_id)), AEADId(int(self.aead_id))
        )
        self.receiverAddress = (ip_recv, port_recv)

    def sendData(self, data):
        match self.mode:
            case 3:
                enc, sender = self.suite_s.create_sender_context(
                    self.suite_s.kem.deserialize_public_key(self.public_key_r),
                    info=self.info,
                    psk=self.psk,
                    psk_id=self.psk_id,
                    sks=self.suite_s.kem.deserialize_private_key(self.private_key_s)
                )
            case 2:
                enc, sender = self.suite_s.create_sender_context(
                    self.suite_s.kem.deserialize_public_key(self.public_key_r),
                    info=self.info,
                    sks=self.suite_s.kem.deserialize_private_key(self.private_key_s)
                )
            case 1:
                enc, sender = self.suite_s.create_sender_context(
                    self.suite_s.kem.deserialize_public_key(self.public_key_r),
                    info=self.info,
                    psk=self.psk,
                    psk_id=self.psk_id
                )
            case 0:
                enc, sender = self.suite_s.create_sender_context(
                    self.suite_s.kem.deserialize_public_key(self.public_key_r),
                    info=self.info
                )

        ciphertext = sender.seal(bytes.fromhex(data["pt"]), aad=bytes.fromhex(data["aad"]))

        datatosend = {
            'encap': enc.hex(),
            'ciphertext': ciphertext.hex()
        }

        jsontosend = json.dumps(datatosend)

        self.sock.sendto(jsontosend.encode(), self.receiverAddress)
        self.sock.close()

    # def sendExcData(self, exc_data):
    #     datatosend = {
    #         'encap': exc_data["enc"],
    #         'ciphertext': exc_data["ct"]
    #     }
    #
    #     jsontosend = json.dumps(datatosend)
    #
    #     self.sock.sendto(jsontosend.encode(), self.receiverAddress)
    #     self.sock.close()


# stringa_input = 0
# while int(stringa_input) not in range(1, 5):
#     stringa_input = input("Scegli quale test eseguire (1-4): ")

for i in range(1,sum([len(d) for r, d, f in os.walk('./testvectors/generated')]) + 1):
    base_path = f'./testvectors/generated/test{i}/'
    sender_json = json.load(open(base_path+"sender.json"))
    data_json = json.load(open(base_path+'data.json'))
    sender = Sender(sender_json, "127.0.0.1", 5005, "127.0.0.1", 5006)
    sender.sendData(data_json)
    print(f"Test vector {i}")
    time.sleep(2)

# for i in range(1, sum([len(d) for r, d, f in os.walk('./testvectors/generated')]) + 1):
#     base_path = f'./testvectors/generated/test{i}/'
#     sender_json = json.load(open(base_path + "sender.json"))
#     exc_data = json.load(open(base_path + "exc_data.json"))
#     sender = Sender(sender_json, "127.0.0.1", 5005, "127.0.0.1", 5006)
#     sender.sendExcData(exc_data)
#     print(f"Test vector {i}")
#     time.sleep(2)
