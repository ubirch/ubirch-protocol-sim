import crypto
import json
import machine
import os
import pycom
import time
import ubinascii as binascii
from network import WLAN, LTE

from helpers import wifi_connect, nb_iot_attach, nb_iot_connect, set_time, bootstrap, get_certificate, register_key, \
    post, get_upp_payload
from ubirch import SimProtocol

print("\n- - - UBIRCH protocol (SIM) - - -\n")

# load some necessary config (request API keys from ubirch)
with open("config.json") as f:
    config = json.load(f)

UPP_SERVER = 'niomon.{}.ubirch.com'.format(config["env"])
KEY_SERVER = 'key.{}.ubirch.com'.format(config["env"])
BOOT_SERVER = 'api.console.{}.ubirch.com'.format(config["env"])

device_name = "ukey"
cert_id = "ucrt"

lte = LTE()

nb_iot_connection = False
if 'wifi' in config:
    # initialize wifi connection
    wlan = WLAN(mode=WLAN.STA)
    if not wifi_connect(wlan, config["wifi"]["ssid"], config["wifi"]["pass"]):
        print("ERROR: unable to connect to network. Resetting device...")
        time.sleep(1)
        machine.reset()
else:
    nb_iot_connection = True
    # initialize NB-IoT connection
    if not nb_iot_attach(lte, config["apn"]):
        print("ERROR: unable to attach to network. Resetting device...")
        time.sleep(1)
        machine.reset()

    if not nb_iot_connect(lte):
        print("ERROR: unable to connect to network. Resetting device...")
        time.sleep(1)
        machine.reset()

if not set_time():
    print("ERROR: unable to set time. Resetting device...")
    time.sleep(1)
    machine.reset()

# initialize the ubirch protocol interface
ubirch = None
try:
    ubirch = SimProtocol(lte=lte, at_debug=config["debug"])
except Exception as e:
    print("ERROR: SIM initialization failed: {} Resetting device...".format(e))
    time.sleep(1)
    machine.reset()

# get IMSI from SIM
imsi = ubirch.get_imsi()
print("IMSI: {}\n".format(imsi))

# check if PIN is known and bootstrap if unknown
pin_file = imsi + ".bin"
pin = ""
if pin_file in os.listdir('.'):
    with open(pin_file, "rb") as f:
        pin = f.readline().decode()
else:
    try:
        pin = bootstrap(imsi, BOOT_SERVER, config["password"])
    except Exception as e:
        print("ERROR: bootstrapping failed: {} Resetting device...".format(e))
        time.sleep(1)
        machine.reset()

    with open(pin_file, "wb") as f:
        f.write(pin.encode())

# use PIN to authenticate against the SIM application
if not ubirch.sim_auth(pin):
    raise Exception("ERROR: PIN not accepted")

# get UUID from SIM
device_uuid = ubirch.get_uuid(device_name)
print("UUID: {}\n".format(device_uuid))

# try to get X.509 certificate from SIM
csr = b''
try:
    csr = ubirch.get_certificate(cert_id)
    print("X.509 certificate [hex]   : " + binascii.hexlify(csr).decode())
    print("X.509 certificate [base64]: " + binascii.b2a_base64(csr).decode())
except Exception as e:
    print("-- no certificate with entry ID \"{}\" found on SIM\n".format(cert_id))

# create a certificate for the device
# todo this will be replaced by the X.509 certificate from the SIM card
print("-- creating self-signed certificate for identity {}\n".format(device_uuid))
csr = get_certificate(device_name, device_uuid, ubirch)
print("certificate: {}\n".format(csr.decode()))

# register public key at ubirch key service
try:
    register_key(KEY_SERVER, config["password"], csr)
except Exception as e:
    print("ERROR: key registration failed: {} Resetting device...".format(e))
    time.sleep(1)
    machine.reset()

interval = 60
pycom.heartbeat(False)  # turn off LED blinking
print("-- starting loop (interval = {} sec)\n".format(interval))
while True:
    pycom.rgbled(0x002200)  # LED green
    start_time = time.time()  # start timer

    # get data and calculate hash of timestamp, UUID and data to ensure hash is unique
    payload_data = binascii.hexlify(crypto.getrandbits(32))

    # create message
    message = '{{"ts":{},"id":"{}","data":"{}"}}'.format(
        start_time,
        device_uuid,
        binascii.b2a_base64(payload_data).decode().rstrip('\n'))
    print("message: {}\n".format(message))

    # generate UPP with the message hash using the automatic hashing functionality of the SIM card
    upp = ubirch.message_chained(device_name, message.encode(), hash_before_sign=True)

    print("hash (SHA256): {}".format(binascii.b2a_base64(get_upp_payload(upp)).decode()))
    print("UPP (msgpack): {} ({})\n".format(binascii.hexlify(upp).decode(), len(upp)))

    # make sure device is still connected before sending data
    if not nb_iot_connection:  # check WIFI
        wlan = WLAN(mode=WLAN.STA)
        if not wlan.isconnected():
            pycom.rgbled(0x440044)  # LED purple
            print("!! lost connection, trying to reconnect ...")
            if not wifi_connect(wlan, config["wifi"]["ssid"], config["wifi"]["pass"]):
                print("ERROR: unable to connect to network. Resetting device...")
                time.sleep(5)
                machine.reset()
    else:  # check NB-IOT
        if not lte.isconnected():
            pycom.rgbled(0x440044)  # LED purple
            print("!! lost connection, trying to reconnect ...")
            if not nb_iot_connect(lte):
                print("ERROR: unable to connect to network. Resetting device...")
                time.sleep(5)
                machine.reset()

    pycom.rgbled(0x002200)  # LED green

    # # # # # # # # # # # # # # # # # # #
    # send message to your backend here #
    # # # # # # # # # # # # # # # # # # #

    # send UPP to ubirch backend
    try:
        post(UPP_SERVER, device_uuid, config["password"], upp)
    except Exception as e:
        print("!! UPP not sent !! {}".format(e))
        # import sys
        # sys.print_exception(e)
        pycom.rgbled(0x440000)  # LED red
        time.sleep(3)

    lte.disconnect()

    # wait for next interval
    passed_time = time.time() - start_time
    if interval > passed_time:
        pycom.rgbled(0)  # LED off
        machine.idle()
        time.sleep(interval - passed_time)
