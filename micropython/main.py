import crypto
import json
import machine
import os
import pycom
import time
import ubinascii as binascii
from network import WLAN, LTE

from helpers import wifi_connect, nb_iot_attach, nb_iot_connect, set_time, bootstrap, get_certificate, register_key, \
    post
from ubirch import SimProtocol

print("** ubirch protocol (SIM) ...")

# load some necessary config (request API keys from ubirch)
with open("config.json") as f:
    config = json.load(f)

UPP_SERVER = 'niomon.{}.ubirch.com'.format(config["env"])
KEY_SERVER = 'key.{}.ubirch.com'.format(config["env"])
BOOT_SERVER = 'https://api.console.{}.ubirch.com'.format(config["env"])

lte = LTE()

# # initialize wifi connection
# wlan = WLAN(mode=WLAN.STA)
# if not wifi_connect(wlan, config["wifi"]["ssid"], config["wifi"]["pass"]):
#     print("ERROR: unable to connect to network. Resetting device...")
#     time.sleep(5)
#     machine.reset()

# initialize NB-IoT connection
if not nb_iot_attach(lte, config["apn"]):
    print("ERROR: unable to attach to network. Resetting device...")
    time.sleep(5)
    machine.reset()

if not nb_iot_connect(lte):
    print("ERROR: unable to connect to network. Resetting device...")
    time.sleep(5)
    machine.reset()

if not set_time():
    print("ERROR: unable to set time. Resetting device...")
    time.sleep(5)
    machine.reset()

# initialize the ubirch protocol interface
ubirch = SimProtocol(lte=lte, at_debug=config["debug"])

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
    pin = bootstrap(imsi, BOOT_SERVER, config["password"], debug=config["debug"])
    with open(pin_file, "wb") as f:
        f.write(pin.encode())

# use PIN to authenticate against the SIM application
if not ubirch.sim_auth(pin):
    raise Exception("PIN not accepted")

# get X.509 certificate from SIM
cert_id = "ucrt"
csr = ubirch.get_certificate(cert_id)
print("X.509 certificate [base64]: " + binascii.b2a_base64(csr).decode().rstrip('\n'))
print("X.509 certificate [hex]   : " + binascii.hexlify(csr).decode())

device_name = "ukey"

# get UUID from SIM
device_uuid = ubirch.get_uuid(device_name)
print("UUID: " + str(device_uuid))

# set headers for http requests to the ubirch backend
HEADERS = [
    'X-Ubirch-Hardware-Id: {}'.format(str(device_uuid)),
    'X-Ubirch-Credential: {}'.format(binascii.b2a_base64(config["password"]).decode().rstrip('\n')),
    'X-Ubirch-Auth-Type: ubirch'
]

# create a certificate for the device and register public key at ubirch key service
# todo this will be replaced by the X.509 certificate from the SIM card
csr = get_certificate(device_name, device_uuid, ubirch)
try:
    r = register_key(KEY_SERVER, csr, config["password"], debug=True)
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

interval = 60
pycom.heartbeat(False)  # turn off LED blinking
while True:
    pycom.rgbled(0x002200)  # LED green
    start_time = time.time()  # start timer

    # get data and calculate hash of timestamp, UUID and data to ensure hash is unique
    payload_data = binascii.hexlify(crypto.getrandbits(32))
    unique_data = "{}{}{}".format(start_time, device_uuid, payload_data)

    # create message
    message = '{{"ts":{},"id":"{}","data":"{}"}}'.format(
        start_time,
        device_uuid,
        binascii.b2a_base64(payload_data).decode().rstrip('\n'))
    print("message: {}".format(message))

    # generate UPP with the data hash using the automatic hashing functionality of the SIM card
    upp = ubirch.message_chained(device_name, unique_data.encode(), hash_before_sign=True)
    print("UPP: {} ({})".format(binascii.hexlify(upp).decode(), len(upp)))

    # make sure device is still connected before sending data
    # if not wlan.isconnected():
    #     pycom.rgbled(0x440044)  # LED purple
    #     print("!! lost connection, trying to reconnect ...")
    #     if not wifi_connect(wlan, config["wifi"]["ssid"], config["wifi"]["pass"]):
    #         print("ERROR: unable to connect to network. Resetting device...")
    #         time.sleep(5)
    #         machine.reset()
    #     else:
    #         pycom.rgbled(0x002200)  # LED green
    if not lte.isconnected():
        pycom.rgbled(0x440044)  # LED purple
        print("!! lost connection, trying to reconnect ...")
        if not nb_iot_connect(lte):
            print("ERROR: unable to connect to network. Resetting device...")
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
