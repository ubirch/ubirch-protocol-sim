import asn1
import json
import machine
import pycom
import sys
import time
import ubinascii as binascii
import urequests as requests

from network import WLAN, LTE

from ubirch import SimProtocol
from uuid import UUID

LED_GREEN = 0x002200
LED_YELLOW = 0x222200
LED_ORANGE = 0x442200
LED_RED = 0x7f0000
LED_PURPLE = 0x220022


def set_led(led_color):
    pycom.heartbeat(False)
    pycom.rgbled(led_color)


def wake_up() -> float:
    set_led(LED_GREEN)
    return time.time()


def sleep_until_next_interval(start_time, interval):
    # wait for next interval
    sleep_time = interval - int(time.time() - start_time)
    if sleep_time > 0:
        print(">> sleep for {} seconds".format(sleep_time))
        set_led(0)  # LED off
        machine.idle()
        time.sleep(sleep_time)


def nb_iot_attach(lte: LTE, apn: str):
    sys.stdout.write(">> attaching to LTE network ({})".format(apn))
    lte.attach(band=8, apn=apn)
    i = 0
    while not lte.isattached() and i < 60:
        machine.idle()  # save power while waiting
        time.sleep(1.0)
        sys.stdout.write(".")
        i += 1
    print("")
    if not lte.isattached():
        raise Exception("unable to attach to LTE network")
    print("-- attached: " + str(i) + "s")


def nb_iot_connect(lte: LTE):
    sys.stdout.write(">> connecting to LTE network")
    lte.connect()  # start a data session and obtain an IP address
    i = 0
    while not lte.isconnected() and i < 30:
        machine.idle()  # save power while waiting
        time.sleep(1.0)
        sys.stdout.write(".")
        i += 1
    print("")
    if not lte.isconnected():
        raise Exception("unable to connect to LTE network")
    print("-- connected ({}s)".format(i))
    # print('-- IP address: ' + str(lte.ifconfig()))


def wifi_connect(wlan: WLAN, ssid: str, pwd: str):
    print(">> connecting to WLAN network \"{}\"".format(ssid))
    try:
        wlan.connect(ssid, auth=(WLAN.WPA2, pwd), timeout=10000)
        while not wlan.isconnected():
            machine.idle()  # save power while waiting
    except OSError:
        raise Exception("unable to connect to WLAN network \"{}\"".format(ssid))
    print("-- connected")
    print("-- IP address: " + str(wlan.ifconfig()))


def set_time():
    rtc = machine.RTC()
    i = 0
    sys.stdout.write(">> setting time")
    rtc.ntp_sync('185.15.72.251', 3600)
    while not rtc.synced() and i < 30:
        machine.idle()  # save power while waiting
        time.sleep(1.0)
        sys.stdout.write(".")
        i += 1
    print("")
    if not rtc.synced():
        raise Exception("unable to set time")
    print("-- current time: {}\n".format(rtc.now()))


def lte_setup(lte: LTE, connect: bool, apn: str or None):
    print(">> initializing LTE")
    lte.init()
    if connect:
        if not lte.isattached():
            nb_iot_attach(lte, apn)
        if not lte.isconnected():
            nb_iot_connect(lte)


def lte_shutdown(lte: LTE, detach=True):
    if lte.isconnected():
        print(">> disconnecting LTE")
        lte.disconnect()
    print(">> de-initializing LTE")
    lte.deinit(detach=detach, reset=False)


def bootstrap(imsi: str, server: str, auth: str) -> str:
    """
    Claim SIM identity at the ubirch backend and return SIM applet PIN to unlock crypto functionality.
    Throws exception if bootstrapping fails.
    :param imsi: the SIM international mobile subscriber identity (IMSI)
    :param server: the bootstrap service URL
    :param auth: the ubirch backend password
    :param debug: enable debug output
    :return: the PIN to authenticate against the SIM card with
    """
    url = 'https://' + server + '/ubirch-web-ui/api/v1/devices/bootstrap'
    headers = {
        'X-Ubirch-IMSI': imsi,
        'X-Ubirch-Credential': binascii.b2a_base64(auth).decode().rstrip('\n'),
        'X-Ubirch-Auth-Type': 'ubirch'
    }
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        print(">> bootstrapping successful\n")
        info = json.loads(r.content)
        return info['pin']
    else:
        raise Exception("request to {} failed with status code {}: {}".format(url, r.status_code, r.text))


def _asn1tosig(data: bytes):
    s1 = asn1.asn1_node_root(data)
    a1 = asn1.asn1_node_first_child(data, s1)
    part1 = asn1.asn1_get_value(data, a1)
    a2 = asn1.asn1_node_next(data, a1)
    part2 = asn1.asn1_get_value(data, a2)
    if len(part1) > 32: part1 = part1[1:]
    if len(part2) > 32: part2 = part2[1:]
    return part1 + part2


def get_certificate(device_id: str, device_uuid: UUID, proto: SimProtocol) -> bytes:
    """
    Get a signed json with the key registration request until CSR handling is in place.
    """
    # TODO fix handling of key validity (will be fixed by handling CSR generation through SIM card)
    TIME_FMT = '{:04d}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}.000Z'
    now = machine.RTC().now()
    created = not_before = TIME_FMT.format(now[0], now[1], now[2], now[3], now[4], now[5])
    later = time.localtime(time.mktime(now) + 30758400)
    not_after = TIME_FMT.format(later[0], later[1], later[2], later[3], later[4], later[5])
    pub_base64 = binascii.b2a_base64(proto.get_key(device_id)).decode()[:-1]
    # json must be compact and keys must be sorted alphabetically
    REG_TMPL = '{{"algorithm":"ecdsa-p256v1","created":"{}","hwDeviceId":"{}","pubKey":"{}","pubKeyId":"{}","validNotAfter":"{}","validNotBefore":"{}"}}'
    REG = REG_TMPL.format(created, str(device_uuid), pub_base64, pub_base64, not_after, not_before).encode()
    # get the ASN.1 encoded signature and extract the signature bytes from it
    signature = _asn1tosig(proto.sign(device_id, REG, 0x00))
    return '{{"pubKeyInfo":{},"signature":"{}"}}'.format(REG.decode(),
                                                         binascii.b2a_base64(signature).decode()[:-1]).encode()


def register_key(server: str, auth: str, certificate: bytes) -> bytes:
    url = 'https://' + server + '/api/keyService/v1/pubkey'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(auth)
    }
    r = requests.post(url=url, headers=headers, data=certificate)
    if r.status_code == 200:
        print(">> key registration successful\n")
        return r.content
    else:
        raise Exception("request to {} failed with status code {}: {}".format(url, r.status_code, r.text))


def post(server: str, uuid: UUID, auth: str, data: bytes) -> bytes:
    url = 'https://' + server + '/'
    headers = {
        'X-Ubirch-Hardware-Id': str(uuid),
        'X-Ubirch-Credential': binascii.b2a_base64(auth).decode().rstrip('\n'),
        'X-Ubirch-Auth-Type': 'ubirch'
    }
    r = requests.post(url=url, data=data, headers=headers)
    if r.status_code == 200:
        print(">> successfully sent UPP\n")
        return r.content
    else:
        raise Exception("request to {} failed with status code {}: {}".format(url, r.status_code, r.content))


def get_upp_payload(upp: bytes) -> bytes:
    """
    Get the payload of a Ubirch Protocol Message
    """
    if upp[0] == 0x95 and upp[1] == 0x22:  # signed UPP
        payload_start_idx = 23
    elif upp[0] == 0x96 and upp[1] == 0x23:  # chained UPP
        payload_start_idx = 89
    else:
        raise Exception("!! can't get payload from {} (not a UPP)".format(binascii.hexlify(upp).decode()))

    payload_len = upp[payload_start_idx - 1]
    return upp[payload_start_idx:payload_start_idx + payload_len]
