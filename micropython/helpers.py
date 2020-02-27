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
    sys.stdout.write("++ attaching to the NB-IoT network")
    while not lte.isattached() and i < 60:
        time.sleep(1.0)
        sys.stdout.write(".")
        i += 1
    print("")
    if lte.isattached():
        print("-- attached: " + str(i) + "s")
        return True
    return False


def nb_iot_connect(lte: LTE) -> bool:
    lte.connect()  # start a data session and obtain an IP address
    i = 0
    sys.stdout.write("++ connecting to the NB-IoT network")
    while not lte.isconnected() and i < 30:
        time.sleep(1.0)
        sys.stdout.write(".")
        i += 1
    print("")
    if lte.isconnected():
        print("-- connected: " + str(i) + "s")
        # print('-- IP address: ' + str(lte.ifconfig()))
        return True
    return False


def set_time() -> bool:
    rtc = machine.RTC()
    i = 0
    sys.stdout.write("++ setting time")
    rtc.ntp_sync('185.15.72.251', 3600)
    while not rtc.synced() and i < 60:
        sys.stdout.write(".")
        time.sleep(1.0)
        i += 1
    print("\n-- current time: " + str(rtc.now()) + "\n")
    return rtc.synced()


def wifi_connect(wlan: WLAN, ssid: str, pwd: str) -> bool:
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
            return True
    return False


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
    pub_base64 = binascii.b2a_base64(proto.get_key(device_id)).decode()[:-1]
    # json must be compact and keys must be sorted alphabetically
    REG_TMPL = '{{"algorithm":"ecdsa-p256v1","created":"{}","hwDeviceId":"{}","pubKey":"{}","pubKeyId":"{}","validNotAfter":"{}","validNotBefore":"{}"}}'
    REG = REG_TMPL.format(created, str(device_uuid), pub_base64, pub_base64, not_after, not_before).encode()
    # get the ASN.1 encoded signature and extract the signature bytes from it
    signature = asn1tosig(proto.sign(device_id, REG, 0x00))
    return '{{"pubKeyInfo":{},"signature":"{}"}}'.format(REG.decode(), binascii.b2a_base64(signature).decode()[:-1])


def request(method: str, server: str, path: str, headers: list, data: bytes = None, debug: bool = False):
    import socket, ssl
    headers += ['Host: {}'.format(server)]
    if data is not None:
        headers += ['Content-Length: {}'.format(len(data))]
    req = '{} {} HTTP/1.0\r\n{}\r\n\r\n'.format(method, path, '\r\n'.join(headers)).encode()
    if debug:
        print("=== REQUEST")
        print(req)
        if data is not None:
            print(data) if isinstance(data, str) else print(binascii.hexlify(data).decode())
        print("===")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sslsock = ssl.wrap_socket(sock)
    socket.dnsserver(1, '8.8.4.4')
    socket.dnsserver(0, '8.8.8.8')
    sslsock.connect(socket.getaddrinfo(server, 443)[0][-1])
    sslsock.send(req)
    if data is not None:
        sslsock.send(data)
    response = sslsock.recv(200)
    if debug:
        print("=== RESPONSE")
        print(response.decode())
        print("===")
    sslsock.close()
    return response


def post(server: str, path: str, headers: list, data: bytes, debug: bool = False) -> any:
    return request("POST", server, path, headers, data, debug)


def get(server: str, path: str, headers: list, debug: bool = False) -> any:
    return request("GET", server, path, headers, debug=debug)


def register_key(server: str, certificate: str, auth: str, debug: bool = False):
    headers = [
        'Content-Type: application/json',
        'Authorization: Bearer {}'.format(auth)
    ]
    return post(server, '/api/keyService/v1/pubkey', headers, certificate.encode(), debug)


def bootstrap(imsi: str, service_url: str, pw: str, debug: bool = False) -> str:
    headers = [
        'X-Ubirch-IMSI: {}'.format(imsi),
        'X-Ubirch-Auth-Type: ubirch',
        'X-Ubirch-Credential: {}'.format(binascii.b2a_base64(pw).decode().rstrip('\n'))
    ]
    response = get(service_url, '/ubirch-web-ui/api/v1/devices/bootstrap/json', headers, debug)

    # todo get PIN from response
    pin = ""
    return pin
