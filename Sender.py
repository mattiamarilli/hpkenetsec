import socket
import json
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey


def __validatePublicKeyReceiver():
    return True


class Sender:
    def __init__(self, config, ip, port, ip_recv, port_recv):
        self.mode = config["pub_data"]["mode"]
        self.kem_id = config["pub_data"]["kem_id"]
        self.kdf_id = config["pub_data"]["kdf_id"]
        self.aead_id = config["pub_data"]["aead_id"]
        self.public_key_s = config["pub_data"]["pk_s"]
        self.public_key_r = config["pub_data"]["pk_r"]
        self.private_key_s = config["info"]["sk"]
        self.info = config["pub_data"]["info"]
        self.psk = config["info"]["psk"]
        self.psk_id = config["info"]["psk_id"]
        self.ip = ip
        self.port = port
        self.sock = socket.socket(socket.AF_INET,  # Internet
                                  socket.SOCK_DGRAM)  # UDP
        self.sock.bind((ip, port))
        self.suite_s = CipherSuite.new(
            KEMId(int(self.kem_id)), KDFId(int(self.kdf_id)), AEADId(int(self.aead_id))
        )
        # self.hpke = hybrid_pke.default()
        self.receiverAddress = (ip_recv, port_recv)

    def sendData(self, data):
        enc, sender = self.suite_s.create_sender_context(
            self.suite_s.kem.deserialize_public_key(bytes.fromhex(self.public_key_r)))
        ciphertext = sender.seal(data["pt"].encode(), aad=data["aad"].encode())

        datatosend = {
            'encap': enc.decode('latin-1'),
            'ciphertext': ciphertext.decode('latin-1'),
            'pk_s': self.public_key_s,
        }

        jsontosend = json.dumps(datatosend)

        self.sock.sendto(jsontosend.encode(), self.receiverAddress)


sender_json = json.load(open('./testvectors/test1/sender.json'))
data_json = json.load(open('./testvectors/test1/data.json'))
sender = Sender(sender_json, "127.0.0.1", 5005, "127.0.0.1", 5006)
sender.sendData(data_json)