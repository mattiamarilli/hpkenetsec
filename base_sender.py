import socket
import hybrid_pke
import json

# create socket and bind
UDP_IP = "127.0.0.1"
UDP_PORT = 5001
sock = socket.socket(socket.AF_INET,  # Internet
                     socket.SOCK_DGRAM)  # UDP

sock.bind((UDP_IP, UDP_PORT))

sock.sendto(b"key plz", (UDP_IP, 5002))
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

message = b"MAMBO JUMBO!"
encap, ciphertext = hpke.seal(public_key_r, info, aad, message)



sock.sendto(encap, (UDP_IP, 5002))
