import crypto
import json
import machine
import os
import sys
import ubinascii as binascii
from network import WLAN, LTE
from machine import RTC

from helpers import *
from ubirch import SimProtocol

def send_at_cmd_pretty(cmd):
    response = lte.send_at_cmd(cmd).split('\r\n')
    for line in response:
        print(line)

def establish_connection():
    #establish LTE connection
    tries = 0
    if not lte.isattached():
        print("Attaching...")
        set_led(LED_ORANGE)
        lte.attach(apn=cfg.get("apn"))    
        while not lte.isattached():
            tries+=1
            if tries > 20*4:
                print("\nResetting...")
                lte.reset()
                machine.reset()
            time.sleep(0.25)
            sys.stdout.write(".")
    else:
        print("Already attached")

    tries=0
    if not lte.isconnected():
        print("Connecting...")
        set_led(LED_YELLOW)
        lte.connect()    
        while not lte.isconnected():
            tries+=1
            if tries > 5*4:
                print("\nResetting...")
                lte.reset()
                machine.reset()
            time.sleep(0.25)
            sys.stdout.write(".")
    else:
        print("Already connected")
        
    set_led(LED_GREEN)

print("\n- - - UBIRCH protocol (SIM) - - -\n")
set_led(LED_RED)

# load some necessary config (request API keys from ubirch)
with open("config.json") as f:
    cfg = json.load(f)

UPP_SERVER = 'niomon.{}.ubirch.com'.format(cfg["env"])
KEY_SERVER = 'key.{}.ubirch.com'.format(cfg["env"])
BOOT_SERVER = 'api.console.{}.ubirch.com'.format(cfg["env"])

device_name = "ukey"
cert_id = "ucrt"

lte = LTE()

if machine.reset_cause() != machine.DEEPSLEEP_RESET:
    #if we are not coming from deepsleep, the modem is probably in a strange state -> reset
    print("Not coming from sleep, resetting modem to be safe...")
    lte.reset()
    lte.init()

establish_connection()

# set time
try:
    set_time()
except Exception as e:
    set_led(LED_PURPLE)
    sys.print_exception(e)
    #lte_shutdown(lte)
    reset()

print("Suspending data session for AT commands")
lte.pppsuspend()


print("Open new APDU channel")
send_at_cmd_pretty('AT+CSIM=10,"0070000001"')

#print("Send AT Commands")
# print('Select Applet')
# send_at_cmd_pretty('AT+CSIM=42,"01A4040010D2760001180002FF34108389C0028B02"')
# print("Authenticate")
# send_at_cmd_pretty('AT+CSIM=18,"012000000432343934"')
# print("Get random data")
# send_at_cmd_pretty('AT+CSIM=10,"81B9002000"')
# print("Get first SS entry")
# send_at_cmd_pretty('AT+CSIM=10,"81A5010000"')


print("Initializing ubirch sim protocol")
# initialize the ubirch protocol interface
ubirch = None
try:
    ubirch = SimProtocol(lte=lte, at_debug=False)
except Exception as e:
    set_led(LED_RED)
    sys.print_exception(e)
    #lte_shutdown(lte)
    reset()

# get IMSI from SIM
imsi = get_imsi(lte)
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
        set_led(LED_ORANGE)
        sys.print_exception(e)
        lte_shutdown(lte)
        reset()

    with open(pin_file, "wb") as f:
        f.write(pin.encode())

# unlock SIM
if not ubirch.sim_auth(pin):
    print("ERROR: PIN not accepted")
    sys.exit(1)

# get UUID from SIM
device_uuid = ubirch.get_uuid(device_name)
print("UUID: {}\n".format(device_uuid))

# # try to get X.509 certificate from SIM
# csr = b''
# try:
#     csr = ubirch.get_certificate(cert_id)
#     print("X.509 certificate [hex]   : " + binascii.hexlify(csr).decode())
#     print("X.509 certificate [base64]: " + binascii.b2a_base64(csr).decode())
# except Exception as e:
#     print("getting X.509 certificate from SIM failed: {}\n".format(e))

#     # create a self-signed certificate for the public key
#     print("-- creating self-signed certificate for identity {}".format(device_uuid))
#     csr = get_certificate(device_name, device_uuid, ubirch)
#     print("cert: {}\n".format(csr.decode()))

#     # register public key at ubirch key service
#     try:
#         print("resp: {}\n".format(register_key(KEY_SERVER, cfg["password"], csr).decode()))
#     except Exception as e:
#         set_led(LED_ORANGE)
#         sys.print_exception(e)
#         lte_shutdown(lte)
#         reset()

# get data
payload_data = binascii.hexlify(crypto.getrandbits(32))

# create message with timestamp, UUID and data to ensure unique hash
message = '{{"ts":{},"id":"{}","data":"{}"}}'.format(
    time.time(),
    device_uuid,
    binascii.b2a_base64(payload_data).decode().rstrip('\n'))
print("\nmessage: {}\n".format(message))

# generate UPP with the message hash using the automatic hashing functionality of the SIM card
try:
    upp = ubirch.message_chained(device_name, message.encode(), hash_before_sign=True)
except Exception as e:
    set_led(LED_RED)
    sys.print_exception(e)
    time.sleep(3)

print("UPP (msgpack): {}\n".format(binascii.hexlify(upp).decode()))
print("hash (SHA256): {}".format(binascii.b2a_base64(get_upp_payload(upp)).decode()))

print("Closing APDU channel")
send_at_cmd_pretty('AT+CSIM=10,"0070800100"')

print("Done with AT commands, resuming data session")
lte.pppresume()



# # # # # # # # # # # # # # # # # # #
# send message to your backend here #
# # # # # # # # # # # # # # # # # # #

# send UPP to ubirch backend
try:
    establish_connection()
    print("Sending UPP")
    post(UPP_SERVER, device_uuid, cfg["password"], upp)
except Exception as e:
    set_led(LED_ORANGE)
    sys.print_exception(e)


print("Disconnect LTE")
lte.disconnect()

print("Deinit LTE")
lte.deinit(detach=False)

print("Going to sleep")
machine.deepsleep(10000)
