import hybrid_pke
import socket
hpke = hybrid_pke.default()
secret_key_r, public_key_r = hpke.generate_key_pair()  # receiver keys, pre-generated

UDP_IP = "127.0.0.1"
UDP_PORT = 5005

sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))

while True:
    data, addr = sock.recvfrom(1024)  # buffer size is 1024 bytes

    #if data == "key plz":
        #sock.sendto(public_key_r, (UDP_IP, UDP_PORT))

    print("received message: %s" % data)

'''
hybrid_pke.Kem.DHKEM_P521
hpke = hybrid_pke.default()
info = b""  # shared metadata, correspondance-level
aad = b""  # shared metadata, message-level

secret_key_r, public_key_r = hpke.generate_key_pair()  # receiver keys, pre-generated

plaintext = hpke.open(encap, secret_key_r, info, aad, ciphertext)
print(plaintext.decode("utf-8"))
'''