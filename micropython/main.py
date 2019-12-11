import crypto
import hashlib
import json
import pycom
import machine
import time
import ubinascii as binascii
from uuid import UUID
from network import LTE, WLAN

from helpers import wifi_connect, nb_iot_attach, nb_iot_connect, get_certificate, register_key, post
from ubirch import Protocol

print("** ubirch protocol (SIM) ...")

# load some necessary config (request API keys from ubirch)
with open("config.json") as f:
    config = json.load(f)

device_uuid = UUID(binascii.unhexlify(config["uuid"]))

UPP_SERVER = 'niomon.{}.ubirch.com'.format(config["env"])
KEY_SERVER = 'key.{}.ubirch.com'.format(config["env"])
HEADERS = [
    'X-Ubirch-Hardware-Id: {}'.format(str(device_uuid)),
    'X-Ubirch-Credential: {}'.format(binascii.b2a_base64(config["api"]["upp"]).decode().rstrip('\n')),
    'X-Ubirch-Auth-Type: ubirch'
]

# TODO take this out if LTE works
# initialize wifi connection
# wlan = WLAN(mode=WLAN.STA)
# wifi_connect(wlan, config["wifi"]["ssid"], config["wifi"]["pass"])

# initialize NB-IoT connection
lte = LTE()
if not nb_iot_attach(lte, config["apn"]):
    print("ERROR: unable to attach to network. Resetting...")
    time.sleep(5)
    machine.reset()

if not nb_iot_connect(lte):
    print("ERROR: unable to connect to network. Resetting...")
    time.sleep(5)
    machine.reset()

# the pycom module restricts the size of SIM command lines, use only single character name!
# G+D personalized cards have a device_name="ukey" (its the index used to access the key)
device_name = "A"

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
else:
    print("!! key registration not sent !! request to {} failed: {}\nResetting...".format(KEY_SERVER, r))
    time.sleep(5)
    machine.reset()

# get public key of device
public_key = ubirch.key_get(device_name)
print("public key: {} ({})".format(binascii.hexlify(public_key).decode(), len(public_key)))

interval = 30
pycom.heartbeat(False)  # turn off LED blinking
while True:
    pycom.rgbled(0x002200)      # LED green
    start_time = time.time()    # start timer

    # get data and calculate hash over timestamp, uuid and data to ensure hash is unique
    payload_data = binascii.hexlify(crypto.getrandbits(32))
    payload_hash = hashlib.sha256("{}{}{}".format(start_time, device_uuid, payload_data)).digest()

    # create message
    message = '{{"ts":{},"id":"{}","data":"{}","hash":"{}"}}'.format(
        start_time,
        device_uuid,
        binascii.b2a_base64(payload_data).decode().rstrip('\n'),  # remove newline at end
        binascii.b2a_base64(payload_hash).decode().rstrip('\n'))  # remove newline at end
    print("message: {}".format(message))

    # generate UPP with hash
    upp = ubirch.message_chained(device_name, payload_hash)
    print("UPP: {} ({})".format(binascii.hexlify(upp).decode(), len(upp)))

    # make sure device is still connected before sending data
    # if not wlan.isconnected():
    #     print("!! lost connection, trying to reconnect ...")
    #     wifi_connect(wlan, config["wifi"]["ssid"], config["wifi"]["pass"])
    if not lte.isconnected():
        pycom.rgbled(0x440044)  # LED violet
        print("!! lost connection, trying to reconnect ...")
        if not nb_iot_connect(lte):
            print("ERROR: unable to connect to network. Resetting...")
            time.sleep(5)
            machine.reset()
        else:
            pycom.rgbled(0x002200)  # LED green

    # # # # # # # # # # # # # # # # # # #
    # send message to your backend here #
    # # # # # # # # # # # # # # # # # # #

    # send UPP to ubirch backend
    r = post(UPP_SERVER, '/', HEADERS, upp, debug=False)
    if '200 OK' in r:
        print(">> successfully sent UPP")
    else:
        print("!! UPP not sent !! request to {} failed: {}".format(UPP_SERVER, r))
        pycom.rgbled(0x440000)  # LED red
        time.sleep(3)

    lte.disconnect()

    # wait for next interval
    passed_time = time.time() - start_time
    if interval > passed_time:
        pycom.rgbled(0)  # LED off
        time.sleep(interval - passed_time)
