[![Università degli studi di Firenze](https://i.imgur.com/1NmBfH0.png)](https://ingegneria.unifi.it)

Made by [Mattia Marilli](https://github.com/mattiamarilli) and [Marco Trambusti](https://github.com/MarcoTrambusti)

### Project goal
The project aims to test the functionality of the new HPKE standard ([RFC 9180](https://datatracker.ietf.org/doc/rfc9180/)) through a Python implementation using the [pyhpke](https://github.com/dajiaji/pyhpke.git) library.

### Project description
A sender and a receiver configured based on information contained in the test vectors. The sender encrypts the message using the library and sends the message and encapsulation to the receiver. The receiver, using the library, decrypts the message and checks if it corresponds to the corresponding plaintext. Additionally, a script has been created for the automatic generation, according to all modes of the standard, of test vectors starting from an array of messages. Sender and receiver communicate throuth an UDP socket.
