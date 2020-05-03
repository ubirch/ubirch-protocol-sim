import crypto
import json
import machine
import os
import sys
import ubinascii as binascii
from network import WLAN, LTE

from error_handling import *
from helpers import *
from ubirch import SimProtocol

print("\n- - - UBIRCH protocol (SIM) - - -\n")

try:
    # mount SD card if there is one
    sd = machine.SD()
    os.mount(sd, '/sd')
    SD_CARD_MOUNTED = True
except OSError:
    SD_CARD_MOUNTED = False

error_handler = ErrorHandler(file_logging_enabled=True, sd_card=SD_CARD_MOUNTED)

# load some necessary config (request API keys from ubirch)
with open("config.json") as f:
    cfg = json.load(f)

UPP_SERVER = 'niomon.{}.ubirch.com'.format(cfg["env"])
KEY_SERVER = 'key.{}.ubirch.com'.format(cfg["env"])
BOOT_SERVER = 'api.console.{}.ubirch.com'.format(cfg["env"])

device_name = "ukey"
cert_id = "ucrt"

lte = LTE()

nb_iot_connection = False
if 'wifi' in cfg:
    # initialize wifi connection
    wlan = WLAN(mode=WLAN.STA)
    try:
        wifi_connect(wlan, cfg["wifi"]["ssid"], cfg["wifi"]["pass"])
    except Exception as e:
        error_handler.log(e, LED_PURPLE, reset=True)
else:
    nb_iot_connection = True
    # check Network Coverage for UE device (i.e LTE modem)
    if not lte.ue_coverage():
        print("!! There seems to be no Netwok Coverage !! Try to attach and connect anyway ...")

    # initialize LTE and connect to LTE network
    try:
        lte_setup(lte, nb_iot_connection, cfg.get("apn"))
    except Exception as e:
        lte_shutdown(lte)
        error_handler.log(e, LED_PURPLE, reset=True)

try:
    set_time()
except Exception as e:
    lte_shutdown(lte)
    error_handler.log(e, LED_PURPLE, reset=True)

# initialize the ubirch protocol interface
ubirch = None
try:
    ubirch = SimProtocol(lte=lte, at_debug=cfg.get("debug", False))
except Exception as e:
    lte_shutdown(lte)
    error_handler.log(e, LED_RED, reset=True)

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
        pin = bootstrap(imsi, BOOT_SERVER, cfg["password"])
    except Exception as e:
        lte_shutdown(lte)
        error_handler.log(e, LED_ORANGE, reset=True)

    with open(pin_file, "wb") as f:
        f.write(pin.encode())

# use PIN to authenticate against the SIM application
if not ubirch.sim_auth(pin):
    error_handler.log("ERROR: PIN not accepted", LED_RED)
    sys.exit(1)

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
    print("getting X.509 certificate from SIM failed: {}\n".format(e))

# create a certificate for the device
# todo this will be replaced by the X.509 certificate from the SIM card
print("-- creating self-signed certificate for identity {}".format(device_uuid))
csr = get_certificate(device_name, device_uuid, ubirch)
print("certificate: {}\n".format(csr.decode()))

# register public key at ubirch key service
try:
    register_key(KEY_SERVER, cfg["password"], csr)
except Exception as e:
    lte_shutdown(lte)
    error_handler.log(e, LED_ORANGE, reset=True)

interval = 60
intervals_without_incident_counter = 0
print("-- starting loop (interval = {} sec)\n".format(interval))
while True:
    print("\n({})".format(intervals_without_incident_counter))
    start_time = wake_up()  # start timer

    # reinitialize LTE and reconnect to LTE network
    try:
        lte_setup(lte, nb_iot_connection, cfg.get("apn"))  # todo check if this is necessary
    except Exception as e:
        lte_shutdown(lte)
        error_handler.log(e, LED_PURPLE, counter=intervals_without_incident_counter, reset=True)

    # reinitialize modem and SIM
    try:
        ubirch.reinit(pin)  # todo check if this is necessary
    except Exception as e:
        lte_shutdown(lte)
        error_handler.log(e, LED_ORANGE, counter=intervals_without_incident_counter, reset=True)

    # get data
    payload_data = binascii.hexlify(crypto.getrandbits(32))

    # create message with timestamp, UUID and data to ensure unique hash
    message = '{{"ts":{},"id":"{}","data":"{}"}}'.format(
        start_time,
        device_uuid,
        binascii.b2a_base64(payload_data).decode().rstrip('\n'))
    print("\nmessage: {}\n".format(message))

    # generate UPP with the message hash using the automatic hashing functionality of the SIM card
    try:
        upp = ubirch.message_chained(device_name, message.encode(), hash_before_sign=True)
    except Exception as e:
        error_handler.log(e, LED_RED, counter=intervals_without_incident_counter)
        intervals_without_incident_counter = 0
        continue

    print("UPP (msgpack): {} ({})\n".format(binascii.hexlify(upp).decode(), len(upp)))
    print("hash (SHA256): {}".format(binascii.b2a_base64(get_upp_payload(upp)).decode()))

    # make sure device is still connected before sending data
    try:
        if nb_iot_connection:
            # check NB-IOT connection
            if not lte.isconnected():
                nb_iot_connect(lte)
        else:
            # check WIFI connection
            wlan = WLAN(mode=WLAN.STA)
            if not wlan.isconnected():
                wifi_connect(wlan, cfg["wifi"]["ssid"], cfg["wifi"]["pass"])
    except Exception as e:
        lte_shutdown(lte)
        error_handler.log(e, LED_PURPLE, counter=intervals_without_incident_counter, reset=True)

    # # # # # # # # # # # # # # # # # # #
    # send message to your backend here #
    # # # # # # # # # # # # # # # # # # #

    # send UPP to ubirch backend
    try:
        post(UPP_SERVER, device_uuid, cfg["password"], upp)
    except Exception as e:
        error_handler.log(e, LED_ORANGE, counter=intervals_without_incident_counter)
        intervals_without_incident_counter = 0
        continue

    lte_shutdown(lte, detach=True)  # todo check if lte.deinit() is necessary here
    intervals_without_incident_counter += 1
    sleep_until_next_interval(start_time, interval)
