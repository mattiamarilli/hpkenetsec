import socket
import hybrid_pke

UDP_IP = "127.0.0.1"
UDP_PORT = 5005
MESSAGE = b"Hello, World!"
print("UDP target IP: %s" % UDP_IP)
print("UDP target port: %s" % UDP_PORT)
print("message: %s" % MESSAGE)
sock = socket.socket(socket.AF_INET,  # Internet
                     socket.SOCK_DGRAM)  # UDP

sock.sendto(b"key plz", (UDP_IP, UDP_PORT))
handshake = True
pkRec = ''

while handshake:
    data, addr = sock.recvfrom(1024)  # buffer size is 1024 bytes
    if data is not None:  # TODO: fare controllo a modo
        handshake = False
        pkRec = data
        print(pkRec)
    print("received message: %s" % data)



sock = socket.socket(socket.AF_INET,  # Internet
                     socket.SOCK_DGRAM)  # UDP
sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))

'''
hpke = hybrid_pke.default()
info = b""  # shared metadata, correspondance-level
aad = b""  # shared metadata, message-level

message = b"MAMBO JUMBO!"
encap, ciphertext = hpke.seal(public_key_r, info, aad, message)
'''
