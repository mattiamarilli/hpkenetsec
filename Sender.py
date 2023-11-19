import socket
import hybrid_pke
import json


def __validatePublicKeyReceiver():
    return True

class Sender:
    def __init__(self, mode, kem_id, kdf_id, aead_id, public_key_s, private_key_s, info, ip, port):
        self.mode = mode
        self.kem_id = kem_id
        self.kdf_id = kdf_id
        self.aead_id = aead_id
        self.public_key_s = public_key_s
        self.private_key_s = private_key_s
        self.info = info
        self.ip = ip
        self.port = port
        self.public_key_r = ""
        self.sock = socket.socket(socket.AF_INET,  # Internet
                                  socket.SOCK_DGRAM)  # UDP
        self.sock.bind((ip, port))
        self.hpke = hybrid_pke.default()
        self.receiverAddress = ""


    def getReceiverPublicKey(self, ip, port):
        handshake = True

        while handshake:
            data, self.receiverAddress = self.sock.recvfrom(1024)  # buffer size is 1024 bytes
            if data is not None:  # TODO: fare controllo a modo
                handshake = False
                self.public_key_r = data

    def sendData(self, plaintext, aad):
        encap, ciphertext = self.hpke.seal(self.public_key_r, self.info, aad, plaintext, sk_s=self.secret_key_s)

        datatosend = {
            'encap': encap.decode('latin-1'),
            'ciphertext': ciphertext.decode('latin-1'),
            'pk_s': self.public_key_s.decode('latin-1'),
        }

        jsontosend = json.dumps(datatosend)

        self.sock.sendto(jsontosend.encode(), self.receiverAddress)

