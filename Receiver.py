import socket
import hybrid_pke
import json


class Receiver:
    def __init__(self, mode, kem_id, kdf_id, aead_id, public_key_r, private_key_r, info, ip, port):
        self.mode = mode
        self.kem_id = kem_id
        self.kdf_id = kdf_id
        self.aead_id = aead_id
        self.public_key_r = public_key_r
        self.private_key_r = private_key_r
        self.info = info
        self.ip = ip
        self.port = port
        self.public_key_r = ""
        self.sock = socket.socket(socket.AF_INET,  # Internet
                                  socket.SOCK_DGRAM)  # UDP
        self.sock.bind((ip, port))
        self.hpke = hybrid_pke.default()
        self.receiverAddress = ""

    def receiveMessage(self,aad):
        while True:
            data, addr = self.sock.recvfrom(1024)  # buffer size is 1024 bytes

            if data == b"key_req":
                self.sock.sendto(self.public_key_s, addr)
                print("Sended public-key to client: %s" % data)
            else:
                decodeddata = json.loads(data)
                plaintext = self.hpke.open(decodeddata["encap"].encode('latin-1'), self.secret_key_r, self.info, aad,
                                      decodeddata["ciphertext"].encode('latin-1'),
                                      pk_s=decodeddata["pk_s"].encode('latin-1'))
                print(plaintext.decode("utf-8"))

