import socket
import json
from pyhpke import AEADId, CipherSuite, KDFId, KEMId


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

    def sendData(self, data, exc):
        match self.mode:
            case 3:
                enc, sender = self.suite_s.create_sender_context(
                    self.suite_s.kem.deserialize_public_key(self.public_key_r), 
                    info=self.info, 
                    psk=self.psk, 
                    psk_id=self.psk_id, 
                    sks= self.suite_s.kem.deserialize_private_key(self.private_key_s)
                )
            case 2:
                enc, sender = self.suite_s.create_sender_context(
                    self.suite_s.kem.deserialize_public_key(self.public_key_r), 
                    info=self.info.encode(), 
                    sks= self.suite_s.kem.deserialize_private_key(self.private_key_s)
                )
            case 1:
                enc, sender = self.suite_s.create_sender_context(
                    self.suite_s.kem.deserialize_public_key(self.public_key_r), 
                    info=self.info.encode(), 
                    psk= self.psk.encode(), 
                    psk_id=self.psk_id.encode()
                )
            case 0:
                enc, sender = self.suite_s.create_sender_context(
                    self.suite_s.kem.deserialize_public_key(self.public_key_r), 
                    info=self.info.encode()
                )

        ciphertext = sender.seal(bytes.fromhex(data["pt"]) ,aad=bytes.fromhex(data["aad"]))
        print(ciphertext.hex())
        print('\u2705' if ciphertext == bytes.fromhex(exc["ct"]) else '\U0000274C')
       
        datatosend = {
            'encap': enc.hex(),
            'ciphertext': ciphertext.hex(),
        }

        jsontosend = json.dumps(datatosend)

        self.sock.sendto(jsontosend.encode(), self.receiverAddress)


sender_json = json.load(open('./testvectors/test1/sender.json'))
data_json = json.load(open('./testvectors/test1/data.json'))
exc_json = json.load(open('./testvectors/test1/exc_data.json'))

sender = Sender(sender_json, "127.0.0.1", 5005, "127.0.0.1", 5006)
sender.sendData(data_json, exc_json)