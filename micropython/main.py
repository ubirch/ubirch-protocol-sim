import crypto
import hashlib
import json
import machine
import os
import pycom
import time
import ubinascii as binascii
from network import WLAN, LTE

from helpers import wifi_connect, nb_iot_attach, nb_iot_connect, set_time, get_certificate, register_key, post, \
    bootstrap
from ubirch import Protocol
from uuid import UUID

print("** ubirch protocol (SIM) ...")

# load some necessary config (request API keys from ubirch)
with open("config.json") as f:
    config = json.load(f)

device_uuid = UUID(binascii.unhexlify(config["uuid"]))
print("** UUID: {}".format(device_uuid))

UPP_SERVER = 'niomon.{}.ubirch.com'.format(config["env"])
KEY_SERVER = 'key.{}.ubirch.com'.format(config["env"])
BOOT_SERVER = 'https://api.console.{}.ubirch.com'.format(config["env"])
HEADERS = [
    'X-Ubirch-Hardware-Id: {}'.format(str(device_uuid)),
    'X-Ubirch-Credential: {}'.format(binascii.b2a_base64(config["api"]["upp"]).decode().rstrip('\n')),
    'X-Ubirch-Auth-Type: ubirch'
]

lte = LTE()

# TODO take this out if LTE works
# initialize wifi connection
wlan = WLAN(mode=WLAN.STA)
if not wifi_connect(wlan, config["wifi"]["ssid"], config["wifi"]["pass"]):
    print("ERROR: unable to connect to network. Resetting device...")
    time.sleep(5)
    machine.reset()

# # initialize NB-IoT connection
# if not nb_iot_attach(lte, config["apn"]):
#     print("ERROR: unable to attach to network. Resetting device...")
#     time.sleep(5)
#     machine.reset()
#
# if not nb_iot_connect(lte):
#     print("ERROR: unable to connect to network. Resetting device...")
#     time.sleep(5)
#     machine.reset()

if not set_time():
    print("ERROR: unable to set time. Resetting device...")
    time.sleep(5)
    machine.reset()

# the pycom module restricts the size of SIM command lines, use only single character name!
device_name = "A"

# initialize the ubirch protocol interface
ubirch = Protocol(lte=lte, at_debug=config["sim"]["debug"])

# get IMSI from SIM
imsi = ubirch.get_imsi()
print("IMSI: " + imsi)

# check if PIN is known and bootstrap if unknown
pin_file = imsi + ".bin"
pin = ""
if pin_file in os.listdir('.'):
    print("loading PIN for " + imsi)
    with open(pin_file, "rb") as f:
        pin = f.readline().decode()
else:
    print("bootstrapping SIM " + imsi)
    pin = bootstrap(imsi, BOOT_SERVER, config["api"]["upp"], debug=config["sim"]["debug"])
    with open(pin_file, "wb") as f:
        f.write(pin.encode())

# use PIN to authenticate against the SIM application
if not ubirch.sim_auth(pin):
    raise Exception("PIN not accepted")

# get X.509 certificate from SIM
csr = ubirch.get_certificate(device_name)
print("X.509 certificate: " + binascii.b2a_base64(csr).decode().rstrip('\n'))

import sys

sys.exit()

# create a certificate for the device and register public key at ubirch key service
# todo this will be replaced by the X.509 certificate from the SIM card
csr = get_certificate(device_name, device_uuid, ubirch)

try:
    r = register_key(KEY_SERVER, csr, config["api"]["key"], debug=True)
    if '200 OK' in r:
        print(">> successfully sent key registration")
    else:
        print("!! key registration not sent !! request to {} failed: {}\nResetting device...".format(KEY_SERVER, r))
        time.sleep(5)
        machine.reset()
except:
    print("ERROR: can't register key, network failure. Resetting device...")
    time.sleep(5)
    machine.reset()

interval = 30
pycom.heartbeat(False)  # turn off LED blinking
while True:
    pycom.rgbled(0x002200)  # LED green
    start_time = time.time()  # start timer

    # get data and calculate hash of timestamp, UUID and data to ensure hash is unique
    payload_data = binascii.hexlify(crypto.getrandbits(32))
    unique_data = "{}{}{}".format(start_time, device_uuid, payload_data)
    data_hash = hashlib.sha256(unique_data).digest()

    # create message
    message = '{{"ts":{},"id":"{}","data":"{}","hash":"{}"}}'.format(
        start_time,
        device_uuid,
        binascii.b2a_base64(payload_data).decode().rstrip('\n'),  # remove newline at end
        binascii.b2a_base64(data_hash).decode().rstrip('\n'))  # remove newline at end
    print("message: {}".format(message))

    # generate UPP with hash
    upp = ubirch.message_chained(device_name, data_hash)
    # upp = ubirch.message_chained(device_name, unique_data.encode(), hash_before_sign=True)  # use automatic hashing
    print("UPP: {} ({})".format(binascii.hexlify(upp).decode(), len(upp)))

    # make sure device is still connected before sending data
    if not wlan.isconnected():
        pycom.rgbled(0x440044)  # LED purple
        print("!! lost connection, trying to reconnect ...")
        if not wifi_connect(wlan, config["wifi"]["ssid"], config["wifi"]["pass"]):
            print("ERROR: unable to connect to network. Resetting device...")
            time.sleep(5)
            machine.reset()
        else:
            pycom.rgbled(0x002200)  # LED green
    # if not lte.isconnected():
    #     pycom.rgbled(0x440044)  # LED purple
    #     print("!! lost connection, trying to reconnect ...")
    #     if not nb_iot_connect(lte):
    #         print("ERROR: unable to connect to network. Resetting device...")
    #         time.sleep(5)
    #         machine.reset()
    #     else:
    #         pycom.rgbled(0x002200)  # LED green

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

    # lte.disconnect()

    # wait for next interval
    passed_time = time.time() - start_time
    if interval > passed_time:
        pycom.rgbled(0)  # LED off
        time.sleep(interval - passed_time)
