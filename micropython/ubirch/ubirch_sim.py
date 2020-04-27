"""
| ubirch-ubirch interface to the G+D SIM Card Application (TLSAUthApp).
|
| This interface wraps the required AT commands necessary to access the
| ubirch-ubirch functionality. To use the application the SIM card interface
| must support the "AT+CSIM" command ([2] 8.17 Generic SIM access +CSIM, p121).
|
| [1] CustomerManual_TLSAuthApp_v1.3.1.pdf
| [2] 3GPP 27007-d60.pdf (not contained in the repository)
|
|
| Copyright 2019 ubirch GmbH
|
| Licensed under the Apache License, Version 2.0 (the "License");
| you may not use this file except in compliance with the License.
| You may obtain a copy of the License at
|
|        http://www.apache.org/licenses/LICENSE-2.0
|
| Unless required by applicable law or agreed to in writing, software
| distributed under the License is distributed on an "AS IS" BASIS,
| WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
| See the License for the specific language governing permissions and
| limitations under the License.
"""

import time
import ubinascii as binascii
from network import LTE
from uuid import UUID

# AT+CSIM=LENGTH,COMMAND

# Application Identifier
APP_DF = 'D2760001180002FF34108389C0028B02'

STK_OK = '9000'  # successful command execution
STK_MD = '6310'  # more data, repeat finishing

# SIM toolkit commands
STK_GET_RESPONSE = '00C00000{:02X}'  # get a pending response
STK_AUTH_PIN = '00200000{:02X}{}'  # authenticate with pin ([1], 2.1.2)

# generic app commands
STK_APP_SELECT = '00A4040010{}'  # APDU Select Application ([1], 2.1.1)
STK_APP_RANDOM = '80B900{:02X}00'  # APDU Generate Secure Random ([1], 2.1.3)
STK_APP_SS_SELECT = '80A50000{:02X}{}'  # APDU Select SS Entry ([1], 2.1.4)
STK_APP_DELETE_ALL = '80E50000'  # APDU Delete All SS Entries
STK_APP_SS_ENTRY_ID_GET = '80B10000{:02X}{}'  # APDU Get SS Entry ID

# ubirch specific commands
STK_APP_KEY_GENERATE = '80B28000{:02X}{}'  # APDU Generate Key Pair ([1], 2.1.7)
STK_APP_KEY_GET = '80CB0000{:02X}{}'  # APDU Get Key ([1], 2.1.9)
STK_APP_SIGN_INIT = '80B5{:02X}00{:02X}{}'  # APDU Sign Init command ([1], 2.2.1)
STK_APP_SIGN_FINAL = '80B6{:02X}00{:02X}{}'  # APDU Sign Update/Final command ([1], 2.2.2)
STK_APP_VERIFY_INIT = '80B7{:02X}00{:02X}{}'  # APDU Verify Signature Init ([1], 2.2.3)
STK_APP_VERIFY_FINAL = '80B8{:02X}00{:02X}{}'  # APDU Verify Signature Update/Final ([1], 2.2.4)

# certificate management
STK_APP_CSR_GENERATE_FIRST = '80BA8000{:02X}{}'  # Generate Certificate Sign Request command ([1], 2.1.8)
STK_APP_CSR_GENERATE_NEXT = '80BA8100{:02X}'  # Get Certificate Sign Request response ([1], 2.1.8)
STK_APP_CERT_STORE = '80E3{:02X}00{:02X}{}'  # Store Certificate
STK_APP_CERT_UPDATE = '80E7{:02X}00{:02X}{}'  # Update Certificate
STK_APP_CERT_GET = '80CC{:02X}0000'  # Get Certificate

APP_UBIRCH_SIGNED = 0x22
APP_UBIRCH_CHAINED = 0x23


class SimProtocol:
    MAX_AT_LENGTH = 110

    def __init__(self, lte: LTE, at_debug: bool = False):
        """
        Initialize the SIM interface. This executes a command to initialize the modem,
        puts it in minimal functional mode and waits for the modem to become ready,
        then selects the SIM application.

        The LTE functionality must be enabled upfront.
        """
        self.lte = lte
        self.DEBUG = at_debug

        # wait until the modem is ready
        self.lte.pppsuspend()
        r = self.lte.send_at_cmd("AT+CFUN?")
        while not ("+CFUN: 1" in r or "+CFUN: 4" in r):
            time.sleep(1)
            r = self.lte.send_at_cmd("AT+CFUN?")

        # select the SignApp
        for _ in range(3):
            code = self._select()
            if code == STK_OK:
                self.lte.pppresume()
                return

        self.lte.pppresume()
        raise Exception("selecting SIM application failed")

    def _select(self) -> str:
        """
        Select the SIM application to execute secure operations.
        """
        (data, code) = self._execute(STK_APP_SELECT.format(APP_DF))
        return code

    def _encode_tag(self, tags: [(int, bytes or str)]) -> str:
        """
        Encode taged arguments for APDU commands.
        :param tags: a list of tuples of the format (tag, data) where data may be bytes or a pre-encoded str
        :return: a hex encoded string, for use with the APDU
        """
        r = ""
        for (tag, data) in tags:
            if isinstance(data, bytes):
                # convert bytes into hex encoded string
                data = binascii.hexlify(data).decode()

            data_len = int(len(data) / 2)
            if data_len > 0xff:
                data_len = (0x82 << 16) | data_len

            r += "{0:02X}{1:02X}{2}".format(tag, data_len, data)
        return r

    def _decode_tag(self, encoded: bytes) -> [(int, bytes)]:
        """
        Decode APDU response data that contains tags.
        :param encoded: the response data with tags to decode
        :return: (tag, data)
        """
        decoded = []
        idx = 0
        while idx < len(encoded):
            tag = encoded[idx]
            data_len = int(encoded[idx + 1])
            idx += 2
            if data_len == 0x82:  # 0x82 indicates the length of the tag data being 2 bytes long
                data_len = int(encoded[idx]) << 8 | int(encoded[idx + 1])
                idx += 2
            if len(encoded[idx:]) < data_len:
                raise Exception("tag %02x has not enough data %d < %d".format(tag, len(encoded[idx:]), data_len))
            endIdx = idx + data_len
            data = encoded[idx:endIdx]
            decoded.append(tuple((tag, data)))
            idx = endIdx
        return decoded

    def _execute(self, cmd: str) -> (bytes, str):
        """
        Execute an APDU command on the SIM card itself.
        :param cmd: the command to execute
        :return: a tuple of (data, code)
        """
        at_cmd = 'AT+CSIM={},"{}"'.format(len(cmd), cmd.upper())
        if self.DEBUG: print("++ " + at_cmd)
        result = [k for k in self.lte.send_at_cmd(at_cmd).split('\r\n') if len(k.strip()) > 0]
        if self.DEBUG: print('-- ' + '\r\n-- '.join([r for r in result]))

        if result[-1] == 'OK':
            response = result[0][7:].split(',')[1]
            data = b''
            code = response[-4:]
            if len(response) > 4:
                data = binascii.unhexlify(response[0:-4])
            return data, code
        else:
            return b'', result[-1]

    def _get_response(self, code: str) -> (bytes, str):
        """
        Get response from the application.
        :param code: the code response from the previous operation.
        :return: a (data, code) tuple as a result of APDU GET RESPONSE
        """
        data = b''
        if code[0:2] == '61':
            (data, code) = self._execute(STK_GET_RESPONSE.format(int(code[2:4], 16)))
        return data, code

    def _get_more_data(self, code: str, data: bytes, cmd: str) -> (bytes, str):
        """
        Append pending data to already retrieved data
        :param code: the code response from the previous operation
        :param data: the data to append more data to
        :param cmd: the command to get the pending data
        :return: a tuple of (data, code)
        """
        while code == STK_MD:
            (moreData, code) = self._execute(cmd)
            data += moreData
        return data, code

    def _select_ss_entry(self, entry_id: str) -> (bytes, str):
        """
        Select an entry from the secure storage of the SIM card
        :param entry_id: the entry ID
        :return: the code response from the operation
        """
        (data, code) = self._execute(STK_APP_SS_SELECT.format(len(entry_id), binascii.hexlify(entry_id).decode()))
        (data, code) = self._get_response(code)
        if code == STK_OK and self.DEBUG:
            print('found entry ID: ' + repr(self._decode_tag(data)))
        return data, code

    def get_imsi(self) -> str:
        """
        Get the international mobile subscriber identity (IMSI) from SIM
        """
        IMSI_LEN = 15
        at_cmd = "AT+CIMI"
        if self.DEBUG: print("++ " + at_cmd)

        self.lte.pppsuspend()
        for _ in range(3):
            result = [k for k in self.lte.send_at_cmd(at_cmd).split('\r\n') if len(k.strip()) > 0]
            if self.DEBUG: print('-- ' + '\r\n-- '.join([r for r in result]))

            if result[-1] == 'OK' and len(result[0]) == IMSI_LEN:
                self.lte.pppresume()
                return result[0]

        self.lte.pppresume()
        raise Exception("no IMSI available")

    def sim_auth(self, pin: str) -> bool:
        """
        Authenticate against the SIM application to be able to use secure operations.
        :param pin: the pin to use for authentication
        :return: True if the operation was successful
        """
        if self.DEBUG: print("authenticating with PIN " + pin)
        self.lte.pppsuspend()
        (data, code) = self._execute(STK_AUTH_PIN.format(len(pin), binascii.hexlify(pin).decode()))
        self.lte.pppresume()
        if code != STK_OK:
            print(code)
        return code == STK_OK

    def random(self, length: int) -> bytes:
        """
        Generate random data.
        :param length: the number of random bytes to generate
        :return: a byte array containing the random bytes
        """
        if self.DEBUG: print("generating random data with length " + str(length))
        self.lte.pppsuspend()
        (data, code) = self._execute(STK_APP_RANDOM.format(length))
        self.lte.pppresume()
        if code == STK_OK:
            return data
        raise Exception(code)

    def erase(self) -> [(int, bytes)]:
        """
        Delete all existing secure memory entries.
        """
        if self.DEBUG: print("erasing ALL SS entries")
        self.lte.pppsuspend()
        (data, code) = self._execute(STK_APP_DELETE_ALL)
        self.lte.pppresume()

        return data, code

    def generate_csr(self, entry_id: str, uuid: UUID) -> bytes:
        """
        +++ THIS METHOD DOES NOT WORK WITH CURRENT PYCOM FIRMWARE +++
        +++ the max. length of AT commands to transmit via UART (using lte.send_at_cmd) is 127 bytes +++
        +++ but the length of the AT command containing certificate attributes is much greater (264 bytes) +++
        [WIP] Request a CSR for the selected key.
        :param entry_id: the key entry_id
        :param uuid: the csr subject uuid
        :return: the CSR bytes
        """
        if self.DEBUG: print("generating CSR for key with entry ID " + entry_id)
        cert_attr = self._encode_tag([
            (0xD4, "DE".encode()),
            (0xD5, "Berlin".encode()),
            (0xD6, "Berlin".encode()),
            (0xD7, "ubirch GmbH".encode()),
            (0xD8, "Security".encode()),
            (0xD9, str(uuid).encode()),
            (0xDA, "info@ubirch.com".encode())
        ])
        cert_args = self._encode_tag([
            (0xD3, bytes([0x00])),
            (0xE7, cert_attr),
            (0xC2, bytes([0x0B, 0x01, 0x00])),
            (0xD0, bytes([0x21]))
        ])
        args = self._encode_tag([
            (0xC4, entry_id.encode()),
            (0xC4, ("_" + entry_id).encode()),
            (0xE5, cert_args)
        ])

        self.lte.pppsuspend()
        (data, code) = self._execute(STK_APP_CSR_GENERATE_FIRST.format(int(len(args) / 2), args))
        (data, code) = self._get_response(code)  # get first part of CSR
        (data, code) = self._get_more_data(code, data, STK_APP_CSR_GENERATE_NEXT.format(0))  # get next part of CSR
        self.lte.pppresume()
        if code == STK_OK:
            return data

        raise Exception(code)

    def get_certificate(self, entry_id: str) -> bytes:
        """
        Retrieve the X.509 certificate for a key with given key entry_id
        :param entry_id: the key entry ID of the corresponding key of the certificate
        :return: the certificate bytes
        """
        if self.DEBUG: print("getting X.509 certificate for key with entry ID " + entry_id)
        self.lte.pppsuspend()
        # select SS certificate entry
        (data, code) = self._select_ss_entry(entry_id)
        if code == STK_OK:
            # get the certificate
            (data, code) = self._execute(STK_APP_CERT_GET.format(0))
            (data, code) = self._get_more_data(code, data, STK_APP_CERT_GET.format(1))
            if code == STK_OK:
                self.lte.pppresume()
                return [tag[1] for tag in self._decode_tag(data) if tag[0] == 0xc3][0]

        self.lte.pppresume()
        raise Exception(code)

    def get_uuid(self, entry_id: str) -> UUID:
        """
        Retrieve the UUID of a given entry_id.
        :param entry_id: the entry ID of the entry to look for
        :return: the UUID
        """
        if self.DEBUG: print("getting UUID from entry ID " + entry_id)
        self.lte.pppsuspend()
        # select SS public key entry
        (data, code) = self._select_ss_entry(entry_id)
        self.lte.pppresume()
        if code == STK_OK:
            # get the UUID
            uuid_bytes = [tag[1] for tag in self._decode_tag(data) if tag[0] == 0xc0][0]
            return UUID(uuid_bytes)

        raise Exception(code)

    def get_verification_key(self, uuid: UUID) -> bytes:
        """
        Get the public key for a given UUID from the SIM storage.
        :param uuid: the entry title of the verification key to look for
        :return: the public key bytes
        """
        if self.DEBUG: print("getting verification key for UUID " + str(uuid))
        self.lte.pppsuspend()
        # get the entry ID that has UUID as entry title
        (data, code) = self._execute(STK_APP_SS_ENTRY_ID_GET.format(int(len(uuid.hex) / 2), uuid.hex))
        (data, code) = self._get_response(code)
        self.lte.pppresume()
        if code == STK_OK:
            key_name = [tag[1] for tag in self._decode_tag(data) if tag[0] == 0xc4][0]
            # get the key with that entry ID
            return self.get_key(key_name.decode())

        raise Exception(code)

    def get_key(self, entry_id: str) -> bytes:
        """
        Retrieve the public key of a given entry_id.
        :param entry_id: the key to look for
        :return: the public key bytes
        """
        if self.DEBUG: print("getting public key with entry ID " + entry_id)
        self.lte.pppsuspend()
        # select SS public key entry
        (data, code) = self._select_ss_entry(entry_id)
        if code == STK_OK:
            # get the key
            args = self._encode_tag([(0xD0, bytes([0x00]))])
            (data, code) = self._execute(STK_APP_KEY_GET.format(int(len(args) / 2), args))
            (data, code) = self._get_response(code)
            if code == STK_OK:
                self.lte.pppresume()
                # remove the fixed 0x04 prefix from the key entry_id
                return [tag[1][1:] for tag in self._decode_tag(data) if tag[0] == 0xc3][0]

        self.lte.pppresume()
        raise Exception(code)

    def generate_key(self, entry_id: str, entry_title: str) -> str:
        """
        # FIXME not working because AT command too long for pycom FW
        Generate a new key pair and store it on the SIM card using the entry_id and the entry_title.
        :param entry_id: the ID of the entry_id in the SIM cards secure storage area. (KEY_ID)
        :param entry_title: the unique title of the key, which corresponds to the UUID of the device.
        :return: the entry_id name or throws an exception if the operation fails
        """
        if self.DEBUG: print("generating key pair with entry ID " + entry_id)
        self.lte.pppsuspend()
        # see ch 4.1.14 ID and Title (ID shall be fix and title the UUID of the device)

        # prefix private key entry id and private key title with a '_'
        # SS entries must have unique keys and titles
        args = self._encode_tag([(0xC4, str.encode(entry_id)),
                                 (0xC0, binascii.unhexlify(entry_title)),
                                 (0xC1, bytes([0x03])),
                                 (0xC4, str.encode("_" + entry_id)),
                                 (0xC0, binascii.unhexlify("_" + entry_title)),
                                 (0xC1, bytes([0x03]))
                                 ])
        (data, code) = self._execute(STK_APP_KEY_GENERATE.format(int(len(args) / 2), args))
        self.lte.pppresume()
        if code == STK_OK:
            return entry_id
        raise Exception(code)

    def sign(self, entry_id: str, value: bytes, protocol_version: int, hash_before_sign: bool = False) -> bytes:
        """
        Sign a message using the given entry_id key.
        :param entry_id: the key to use for signing
        :param value: the message to sign
        :param protocol_version: 0x00 = regular signing
                                 0x22 = Ubirch Proto v2 signed message
                                 0x23 = Ubirch Proto v2 chained message
        :param hash_before_sign: the message will be hashed before it is used to build the UPP
        :return: the signed message or throws an exceptions if failed
        """
        self.lte.pppsuspend()
        args = self._encode_tag([(0xC4, str.encode('_' + entry_id)), (0xD0, bytes([0x21]))])
        if hash_before_sign:
            protocol_version |= 0x40  # set flag for automatic hashing
        (data, code) = self._execute(STK_APP_SIGN_INIT.format(protocol_version, int(len(args) / 2), args))
        if code == STK_OK:
            args = binascii.hexlify(value).decode()
            # split command into smaller chunks and handle the last chunk differently
            chunk_size = self.MAX_AT_LENGTH - len(STK_APP_SIGN_FINAL[:-2].format(0, 0))
            chunks = [args[i:i + chunk_size] for i in range(0, len(args), chunk_size)]
            for chunk in chunks[:-1]:
                (data, code) = self._execute(STK_APP_SIGN_FINAL.format(0, int(len(chunk) / 2), chunk))
                if code != STK_OK: break
            else:
                (data, code) = self._execute(STK_APP_SIGN_FINAL.format(1 << 7, int(len(chunks[-1]) / 2), chunks[-1]))
            (data, code) = self._get_response(code)
            if code == STK_OK:
                self.lte.pppresume()
                return data

        self.lte.pppresume()
        raise Exception(code)

    def verify(self, entry_id: str, value: bytes, protocol_version: int) -> bool:
        """
        Verify a signed message using the given entry_id key.
        :param entry_id: the key to use for verification
        :param value: the message to verify
        :param protocol_version: 0xx0 = regular verification
                                 0x22 = Ubirch Proto v2 signed message
                                 0x23 = Ubirch Proto v2 chained message
        :return: the verification response or throws an exceptions if failed
        """
        self.lte.pppsuspend()
        args = self._encode_tag([(0xC4, str.encode(entry_id)), (0xD0, bytes([0x21]))])
        (data, code) = self._execute(STK_APP_VERIFY_INIT.format(protocol_version, int(len(args) / 2), args))
        if code == STK_OK:
            args = binascii.hexlify(value).decode()
            # split command into smaller chunks and handle the last chunk differently
            chunk_size = self.MAX_AT_LENGTH - len(STK_APP_VERIFY_FINAL[:-2].format(0, 0))
            chunks = [args[i:i + chunk_size] for i in range(0, len(args), chunk_size)]
            for chunk in chunks[:-1]:
                (data, code) = self._execute(STK_APP_VERIFY_FINAL.format(0, int(len(chunk) / 2), chunk))
                if code != STK_OK: break
            else:
                (data, code) = self._execute(STK_APP_VERIFY_FINAL.format(1 << 7, int(len(chunks[-1]) / 2), chunks[-1]))
            self.lte.pppresume()
            return code == STK_OK

        self.lte.pppresume()
        raise Exception(code)

    def message_signed(self, name: str, payload: bytes, hash_before_sign: bool = False) -> bytes:
        """
        Create a signed ubirch message (UPP)
        :param name: the key entry_id to use for signing
        :param payload: the data to be included in the message
        :param hash_before_sign: payload will be hashed before it is used to build the UPP
        :return: the signed message or throws an exceptions if failed
        """
        return self.sign(name, payload, APP_UBIRCH_SIGNED, hash_before_sign=hash_before_sign)

    def message_chained(self, name: str, payload: bytes, hash_before_sign: bool = False) -> bytes:
        """
        Create a chained ubirch message (UPP)
        :param name: the key entry_id to use for signing
        :param payload: the data to be included in the message
        :param hash_before_sign: payload will be hashed before it is used to build the UPP
        :return: the chained message or throws an exceptions if failed
        """
        return self.sign(name, payload, APP_UBIRCH_CHAINED, hash_before_sign=hash_before_sign)

    def message_verify(self, name: str, upp: bytes) -> bool:
        """
        Verify a ubirch protocol message.
        :param name: the name of the key entry_id to use (i.e. a servers public key)
        :param upp: the UPP to verify
        :return: whether the message can be verified
        """
        if upp[1] == APP_UBIRCH_SIGNED:
            return self.verify(name, upp, APP_UBIRCH_SIGNED)
        elif upp[1] == APP_UBIRCH_CHAINED:
            return self.verify(name, upp, APP_UBIRCH_CHAINED)
        else:
            return self.verify(name, upp, 0x00)
