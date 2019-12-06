import hashlib
import json
import time

import crypto
import pycom
import ubinascii as binascii
from network import LTE

from helpers import wifi_connect, nb_iot_connect, get_certificate, register_key, post
from ubirch import Protocol
from uuid import UUID

print("** ubirch protocol (SIM) ...")

# load some necessary config (request API keys from ubirch)
with open("config.json") as f:
    config = json.load(f)
UPP_SERVER = 'niomon.{}.ubirch.com'.format(config["env"])
KEY_SERVER = 'key.{}.ubirch.com'.format(config["env"])

# TODO take this out if LTE works
# initialize wifi connection
wifi_connect(config["wifi"]["ssid"], config["wifi"]["pass"])

# initialize NB-IoT connection
lte = LTE()
#nb_iot_connect(lte, config["apn"])

# the pycom module restricts the size of SIM command lines, use only single character name!
# G+D personalized cards have a device_name="ukey" (its the index used to access the key)
device_name = "A"
device_uuid = UUID(binascii.unhexlify(config["uuid"]))

# initialize the ubirch protocol interface
ubirch = Protocol(lte=lte, pin=config["sim"]["pin"], at_debug=config["sim"]["debug"])

try:
    ubirch.key_generate(device_name, device_uuid.hex)
except Exception as e:
    print("key pair may already exist: {}: {}".format(device_name, repr(e.args)))

# create a certificate for the device and register public key at ubirch key service
csr = get_certificate(device_name, device_uuid, ubirch)
r = register_key(KEY_SERVER, csr, config["api"]["key"], debug=False)
if '200 OK' in r:
    print(">> successfully sent key registration")

# get public key of device
public_key = ubirch.key_get(device_name)
print("public key: {} ({})".format(binascii.hexlify(public_key).decode(), len(public_key)))

interval = 60
while True:
    # start a timer
    start_time = time.time()

    payload_data = binascii.hexlify(crypto.getrandbits(32))
    payload_hash = hashlib.sha256("{}{}{}".format(start_time, device_uuid, payload_data)).digest()

    # create message and hash of the message
    data = '{{"ts":{},"id":"{}","data":"{}","hash":"{}"}}'.format(
        time.time(),
        device_uuid,
        binascii.b2a_base64(payload_data).decode().rstrip('\n'), # remove newline at end
        binascii.b2a_base64(payload_hash).decode().rstrip('\n')) # remove newline at end
    print("message: {}".format(data))

    # send message to your backend here

    # generate UPP
    upp = ubirch.message_signed(device_name, payload_hash)
    print("UPP: {} ({})".format(binascii.hexlify(upp).decode(), len(upp)))
    headers = [
        'X-Ubirch-Hardware-Id: {}'.format(str(device_uuid)),
        'X-Ubirch-Credential: {}'.format(binascii.b2a_base64(config["api"]["upp"]).decode('utf-8').rstrip('\n')),
        'X-Ubirch-Auth-Type: ubirch'
    ]
    r = post(UPP_SERVER, '/', headers, upp, debug=False)
    if '200 OK' in r:
        print(">> successfully sent UPP")
    else:
        print(r)

    # wait for next interval
    pycom.heartbeat(False)
    passed_time = time.time() - start_time
    if interval > passed_time:
        pycom.rgbled(0)
        time.sleep(interval - passed_time)
