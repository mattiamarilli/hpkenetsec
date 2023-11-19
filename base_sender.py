import socket
import hybrid_pke
import json

# create socket and bind
UDP_IP = "127.0.0.1"
UDP_PORT = 5001
sock = socket.socket(socket.AF_INET,  # Internet
                     socket.SOCK_DGRAM)  # UDP

sock.bind((UDP_IP, UDP_PORT))

sock.sendto(b"key_req", (UDP_IP, 5002))
handshake = True
public_key_r = ''

while handshake:
    data, addr = sock.recvfrom(1024)  # buffer size is 1024 bytes
    if data is not None:  # TODO: fare controllo a modo
        handshake = False
        public_key_r = data

hpke = hybrid_pke.default()
info = b""  # shared metadata, correspondance-level
aad = b""  # shared metadata, message-level
secret_key_s, public_key_s = hpke.generate_key_pair()  # receiver keys, pre-generated

message = b"MAMBO JUMBO!"
encap, ciphertext = hpke.seal(public_key_r, info, aad, message, sk_s = secret_key_s)

datatosend = {
    'encap': encap.decode('latin-1'),
    'ciphertext':  ciphertext.decode('latin-1'),
    'pk_s': public_key_s.decode('latin-1'),
}

jsontosend = json.dumps(datatosend)

sock.sendto(jsontosend.encode(), addr)
