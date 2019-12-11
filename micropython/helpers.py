import binascii
import sys
import time

import machine
from network import WLAN, LTE

import asn1
from ubirch import Protocol
from uuid import UUID


def nb_iot_attach(lte: LTE, apn: str) -> bool:
    lte.attach(band=8, apn=apn)
    i = 0
    print("++ attaching to the NB IoT network")
    while not lte.isattached() and i < 20:
        time.sleep(1.0)
        sys.stdout.write(".")
        i = i + 1
    print("")
    if lte.isattached():
        print("attached: " + str(i) + "s")
        return True
    return False 


def nb_iot_connect(lte: LTE) -> bool:
    lte.connect()  # start a data session and obtain an IP address
    i = 0
    print("++ connecting to the NB IoT network")
    while not lte.isconnected() and i < 20:
        time.sleep(0.5)
        sys.stdout.write(".")
        i = i + 1
    print("")
    if lte.isconnected():
        print("connected: " + str(i * 2) + "s")
        # print('-- IP address: ' + str(lte.ifconfig()))
        return True
    return False


def set_time() -> bool:
    rtc = machine.RTC()
    i = 0
    rtc.ntp_sync('185.15.72.251', 3600)
    while not rtc.synced() and i < 120:
        sys.stdout.write(".")
        time.sleep(1)
        i = i + 1
    print("\n-- current time: " + str(rtc.now()) + "\n")
    return rtc.synced()


def wifi_connect(wlan: WLAN, ssid: str, pwd: str):
    nets = wlan.scan()
    print("-- searching for wifi networks...")
    for net in nets:
        if net.ssid == ssid:
            print('-- wifi network ' + net.ssid + ' found, connecting ...')
            wlan.connect(ssid, auth=(net.sec, pwd), timeout=5000)
            while not wlan.isconnected():
                machine.idle()  # save power while waiting
            print('-- wifi network connected')
            print('-- IP address: ' + str(wlan.ifconfig()))
            rtc = machine.RTC()
            rtc.ntp_sync('pool.ntp.org', 3600)
            while not rtc.synced():
                time.sleep(1)
            print('-- current time: ' + str(rtc.now()))
            break


def asn1tosig(data: bytes):
    s1 = asn1.asn1_node_root(data)
    a1 = asn1.asn1_node_first_child(data, s1)
    part1 = asn1.asn1_get_value(data, a1)
    a2 = asn1.asn1_node_next(data, a1)
    part2 = asn1.asn1_get_value(data, a2)
    if len(part1) > 32: part1 = part1[1:]
    if len(part2) > 32: part2 = part2[1:]
    return part1 + part2


def get_certificate(device_id: str, device_uuid: UUID, proto: Protocol) -> str:
    """
    Get a signed json with the key registration request until CSR handling is in place.
    """
    # TODO fix handling of key validity (will be fixed by handling CSR generation through SIM card)
    TIME_FMT = '{:04d}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}.000Z'
    now = machine.RTC().now()
    created = not_before = TIME_FMT.format(now[0], now[1], now[2], now[3], now[4], now[5])
    later = time.localtime(time.mktime(now) + 30758400)
    not_after = TIME_FMT.format(later[0], later[1], later[2], later[3], later[4], later[5])
    pub_base64 = binascii.b2a_base64(proto.key_get(device_id)).decode()[:-1]
    # json must be compact and keys must be sorted alphabetically
    REG_TMPL = '{{"algorithm":"ecdsa-p256v1","created":"{}","hwDeviceId":"{}","pubKey":"{}","pubKeyId":"{}","validNotAfter":"{}","validNotBefore":"{}"}}'
    REG = REG_TMPL.format(created, str(device_uuid), pub_base64, pub_base64, not_after, not_before).encode()
    # get the ASN.1 encoded signature and extract the signature bytes from it
    signature = asn1tosig(proto.sign(device_id, REG, 0x00))
    return '{{"pubKeyInfo":{},"signature":"{}"}}'.format(REG.decode(), binascii.b2a_base64(signature).decode()[:-1])


def post(server: str, path: str, headers: list, data: bytes, debug: bool = False) -> any:
    import socket, ssl
    headers = ['Host: {}'.format(server), 'Content-Length: {}'.format(len(data))] + headers
    req = 'POST {} HTTP/1.0\r\n{}\r\n\r\n'.format(path, '\r\n'.join(headers)).encode()
    if debug:
        print("=== REQUEST")
        print(req)
        print(data) if isinstance(data, str) else print(binascii.hexlify(data).decode())
        print("===")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sslsock = ssl.wrap_socket(sock)
    socket.dnsserver(1, '8.8.4.4')
    socket.dnsserver(0, '8.8.8.8')
    sslsock.connect(socket.getaddrinfo(server, 443)[0][-1])
    sslsock.send(req)
    sslsock.send(data)
    response = sslsock.recv(200)
    if debug:
        print("=== RESPONSE")
        print(response.decode())
        print("===")
    sslsock.close()
    return response


def register_key(server: str, certificate: str, auth: str, debug: bool = False):
    headers = [
        'Content-Type: application/json',
        'Authorization: Bearer {}'.format(auth)
    ]
    return post(server, '/api/keyService/v1/pubkey', headers, certificate.encode(), debug)
