import json
from Sender import Sender
from Receiver import Receiver

sender_json = json.load(open('./testvectors/test1/sender.json'))
receiver_json = json.load(open('./testvectors/test1/receiver.json'))
data_json = json.load(open('./testvectors/test1/data.json'))

sender = Sender(sender_json, "127.0.0.1", 5001, "127.0.0.1", 5002)
receiver= Receiver(receiver_json, "127.0.0.1", 5002)

receiver.listen(data_json["aad"])
sender.sendData(data_json)