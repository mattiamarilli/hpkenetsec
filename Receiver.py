import socket
import json
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey


class Receiver:
    def __init__(self, config, ip, port):
        self.mode = config["pub_data"]["mode"]
        self.kem_id = config["pub_data"]["kem_id"]
        self.kdf_id = config["pub_data"]["kdf_id"]
        self.aead_id = config["pub_data"]["aead_id"]
        self.public_key_s = config["pub_data"]["pk_s"]
        self.public_key_r = config["pub_data"]["pk_r"]
        self.private_key_r = config["info"]["sk"]
        self.info = config["pub_data"]["info"]
        self.psk = config["info"]["psk"]
        self.psk_id = config["info"]["psk_id"]
        self.ip = ip
        self.port = port
        self.sock = socket.socket(socket.AF_INET,  # Internet
                                  socket.SOCK_DGRAM)  # UDP
        self.sock.bind((ip, port))
        # self.hpke = hybrid_pke.default()
        # self.receiverAddress = ""

    def listen(self, aad):
        print("waiting 1 ...")
        while True:
            print("waiting ...")
            data, addr = self.sock.recvfrom(1024)  # buffer size is 1024 bytes
            if data == b"key_req":
                self.sock.sendto(self.public_key_s, addr)
                print("Sended public-key to client: %s" % data)
            else:
                decodeddata = json.loads(data)
                suite_r = CipherSuite.new(
                    KEMId(int(self.kem_id)), KDFId(int(self.kdf_id)), AEADId(int(self.aead_id))
                )
                recipient = suite_r.create_recipient_context(decodeddata["encap"].encode('latin-1'),
                                                             suite_r.kem.deserialize_private_key(
                                                                 bytes.fromhex(self.private_key_r)))
                pt = recipient.open(decodeddata["ciphertext"].encode('latin-1'), aad=aad)
                # plaintext = self.hpke.open(, self.secret_key_r, self.info, aad,
                #                       decodeddata["ciphertext"].encode('latin-1'),
                #                       pk_s=decodeddata["pk_s"].encode('latin-1'))
                print(pt.decode("utf-8"))


receiver_json = json.load(open('./testvectors/test1/receiver.json'))
data_json = json.load(open('./testvectors/test1/data.json'))
receiver = Receiver(receiver_json, "127.0.0.1", 5006)
receiver.listen(data_json["aad"])
