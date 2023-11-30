[![Università degli studi di Firenze](https://i.imgur.com/1NmBfH0.png)](https://ingegneria.unifi.it)

Made by [Mattia Marilli](https://github.com/mattiamarilli) and [Marco Trambusti](https://github.com/MarcoTrambusti)

### Project goal
The project aims to test the functionality of the new HPKE standard ([RFC 9180](https://datatracker.ietf.org/doc/rfc9180/)) through a Python implementation using the [pyhpke](https://github.com/dajiaji/pyhpke.git) library.

### How it works?

#### Mode 1

A sender and a receiver are configured based on information contained in the sender.json and receiver.json files of single test vectors. The sender encrypts the message contained in the data.json file using the library and sends the ciphertext and the encapsulation to the receiver through an UDP socket. The receiver, using the library, decrypts the message and checks if it corresponds to the right plaintext. 

#### Mode 2

The sender only takes the exc_data.json file which contains the information from a previous encryption, then send this to the receiver, through an UDP socket, which is configured with the information inside the sender.json file of the test vector correlated with the exc_data information.

#### Test Vector Generation

A script has been created for the automatic generation, according to all modes of the standard, of test vectors starting from an array of messages.

#### Run the scripts

First run the receiver script which will listen on the assigned port, then run the sender which will forward the data according to the chosen mode
