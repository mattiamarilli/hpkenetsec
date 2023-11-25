import socket
import hybrid_pke
import json
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey


def __validatePublicKeyReceiver():
    return True


class Sender:
    def __init__(self, config, ip, port):
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
            hex(self.kem_id), hex(self.kdf_id), hex(self.aead_id)
        )
        self.hpke = hybrid_pke.default()
        self.receiverAddress = ""

    def sendData(self, plaintext, aad):
        encap, ciphertext = self.hpke.seal(self.public_key_r, self.info, aad, plaintext, sk_s=self.secret_key_s)

        datatosend = {
            'encap': encap.decode('latin-1'),
            'ciphertext': ciphertext.decode('latin-1'),
            'pk_s': self.public_key_s.decode('latin-1'),
        }

        jsontosend = json.dumps(datatosend)

        self.sock.sendto(jsontosend.encode(), self.receiverAddress)
