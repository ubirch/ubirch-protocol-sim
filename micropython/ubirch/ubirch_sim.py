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

# AT+CSIM=LENGTH,COMMAND

# Application Identifier
APP_DF = 'D2760001180002FF34108389C0028B02'

STK_OK = '9000'  # successful command execution
STK_MD = '6310'  # more data, repeat finishing

# SIM toolkit commands 
STK_GET_RESPONSE = '00C00000{:02X}'  # get a pending response
STK_AUTH_PIN = '00200000{:02X}{}'  # authenticate with pin

# generica app commands
STK_APP_SELECT = '00A4040010{}'  # APDU Select Application
STK_APP_RANDOM = '80B900{:02X}00'  # APDU Generate Secure Random ([1], 4.2.7, page 50)
STK_APP_DELETE_ALL = '80E50000'  # APDU Delete All SS Entries ([1], 4.1.7, page 30)
STK_APP_SS_SELECT = '80A50000{:02X}{}'  # APDU Select SS Entry ([1], 4.1.2, page 25)

# ubirch ubirch specific commands
STK_APP_KEY_GENERATE = '80B28000{:02X}{}'  # APDU Generate Key Pair
STK_APP_KEY_GET = '80CB0000{:02X}{}'  # APDU Get Key
STK_APP_SIGN_INIT = '80B5{:02X}00{:02X}{}'  # APDU Sign Init command ([1], page 14)
STK_APP_SIGN_FINAL = '80B6{:02X}00{:02X}{}'  # APDU Sign Update/Final command ([1], page 15)
STK_APP_VERIFY_INIT = '80B7{:02X}00{:02X}{}'  # APDU Verify Signature Init ([1], page 11)
STK_APP_VERIFY_FINAL = '80B8{:02X}00{:02X}{}'  # APDU Verify Signature Update/Final ([1], page 12)

# certificate management
STK_APP_CSR_GENERATE = '80BA{:02X}00{:02X}{}'  # Generate Certificate Sign Request command ([1], page 5)

APP_UBIRCH_SIGNED = 0x22
APP_UBIRCH_CHAINED = 0x23


class Protocol:
    DEBUG = False
    MAX_AT_LENGTH = 72

    def __init__(self, lte: LTE, pin: str, at_debug: bool = False):
        """
        Initialize the SIM interface. This executes a command to initialize the modem,
        puts it in minimal functional mode and waits for the modem to become ready,
        then selects the SIM application and authenticates using the pin.

        The LTE functionality must be enabled upfront.

        :param pin: pin to authenticate with
        """
        self.lte = lte
        self.DEBUG = at_debug

        # wait until the modem is ready
        self.lte.pppsuspend()
        r = self.lte.send_at_cmd("AT+CFUN?")
        while not ("+CFUN: 1" in r or "+CFUN: 4" in r):
            time.sleep(1)
            r = self.lte.send_at_cmd("AT+CFUN?")
        self.lte.pppresume()

        # select the SignApp and check pin
        self.select()
        self.pin = pin
        if not self.sim_auth(self.pin):
            raise Exception("PIN not accepted")

    def _encode_tag(self, tags: [(int, bytes or str)]) -> str:
        """
        Encode taged arguments for APDU commands.
        :param tags: a list of tuples of the format (tag, value) where value may be bytes or a pre-encoded str
        :return: a hex encoded string, for use with the APDU
        """
        r = ""
        for (tag, data) in tags:
            if isinstance(data, bytes):
                r += "{0:02X}{1:02X}{2}".format(tag, len(data), binascii.hexlify(data).decode())
            elif isinstance(data, str):
                r += "{0:02X}{1:02X}{2}".format(tag, int(len(data) / 2), data)
            else:
                raise Exception("tag data must be bytes or str")
        return r

    def _decode_tag(self, value: bytes) -> [(int, bytes)]:
        """
        Decode APDU response data that contains tags.
        :param value: the response data with tags to decode
        :return: (tag, value, end index)
        """
        decoded = []
        idx = 0
        while idx < len(value):
            endIdx = idx + int(value[idx + 1]) + 2
            decoded.append(tuple((value[idx], value[idx + 2:endIdx])))
            idx = endIdx
        return decoded

    def _execute(self, cmd: str) -> (bytes, str):
        """
        Execute an APDU command on the SIM card itself.
        :param cmd: the command to execute
        :return: a tuple of (data, code)
        """
        atcmd = 'AT+CSIM={},"{}"'.format(len(cmd), cmd.upper())
        if self.DEBUG: print("++ " + atcmd)
        result = [k for k in self.lte.send_at_cmd(atcmd).split('\r\n') if len(k.strip()) > 0]
        if self.DEBUG: print('-- ' + '\r\n-- '.join([r for r in result]))
        
        if result[-1] == 'OK':
            result = result[0][7:].split(',')[1]
            data = b''
            code = result[-4:]
            if len(result) > 2:
                data = binascii.unhexlify(result[0:-4])
            return data, code
        else:
            return [], result[-1]

    def _get_response(self, code: str):
        """
        Get response from the application.
        :param code: the code response from the previous operation.
        :return: a (data, code) tuple as a result of APDU GET RESPONSE
        """
        if code[0:2] == '61':
            (data, code) = self._execute(STK_GET_RESPONSE.format(int(code[2:4], 16)))
            if code == STK_OK:
                return data, code
            elif code == STK_MD:
                (data2, code) = self._execute(STK_APP_SIGN_FINAL.format(0x81, 0, ""))
                if code == STK_OK:
                    return (data + data2), code
            raise Exception(code)
        else:
            raise Exception(code)

    def select(self):
        """
        Select the SIM application to execute secure operations.
        """
        self.lte.pppsuspend()
        self._execute(STK_APP_SELECT.format(APP_DF))
        self.lte.pppresume()

    def sim_auth(self, pin: str) -> bool:
        """
        Authenticate agains the SIM application to be able to use secure operations.
        :param pin: the pin to use for authentication
        :return: True if the operation was successful
        """
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
        self.lte.pppsuspend()
        (data, code) = self._execute("80E50000")
        (data, code) = self._get_response(code)
        self.lte.pppresume()

        return data, code

    def get_csr(self, entry_id: str) -> bytes:
        """
        [WIP] Request a CSR from one of the selected key.
        :param entry_id: the key entry_id
        :return: the CSR
        """
        self.lte.pppsuspend()
        (data, code) = self._execute(
            STK_APP_SS_SELECT.format(len("_" + entry_id), binascii.hexlify("_" + entry_id).decode()))
        (data, code) = self._get_response(code)
        if code == STK_OK:
            # tags = [(tag, value.decode()) for (tag,value) in ]
            if self.DEBUG: print('Found entry_id: ' + repr(self._decode_tag(data)))
            cert_args = self._encode_tag([
                (0xD3, bytes([0x00])),
                (0xE7, bytes()),
                (0xC2, bytes([0x0B, 0x01, 0x00])),
                (0xD0, bytes([0x21]))
            ])
            args = self._encode_tag([
                (0xC4, str.encode(entry_id)),
                (0xE5, cert_args)
            ])
            (data, code) = self._execute(STK_APP_CSR_GENERATE.format(0x80, int(len(args) / 2), args))
            (data, code) = self._get_response(code)
            self.lte.pppresume()
            return data

        self.lte.pppresume()
        raise Exception(code)

    def key_get(self, entry_id: str) -> [(int, bytes)]:
        """
        Retrieve the public key of a given entry_id.
        :param entry_id: the key to look for
        :return: the public key bytes
        """
        self.lte.pppsuspend()
        (data, code) = self._execute(
            STK_APP_SS_SELECT.format(len("_" + entry_id), binascii.hexlify("_" + entry_id).decode()))
        (data, code) = self._get_response(code)
        if code == STK_OK:
            # tags = [(tag, value.decode()) for (tag,value) in ]
            if self.DEBUG: print('Found entry_id: ' + repr(self._decode_tag(data)))
            args = self._encode_tag([(0xD0, bytes([0x00]))])
            (data, code) = self._execute(STK_APP_KEY_GET.format(int(len(args) / 2), args))
            (data, code) = self._get_response(code)
            self.lte.pppresume()
            # remove the fixed 0x04 prefix from the key entry_id
            return [tag[1][1:] for tag in self._decode_tag(data) if tag[0] == 195][0]
       
        self.lte.pppresume()
        raise Exception(code)

    def key_generate(self, entry_id: str, entry_title: str) -> str:
        """
        Generate a new key pair and store it on the SIM card using the entry_id and the entry_title.
        :param entry_id: the ID of the entry_id in the SIM cards secure storage area. (KEY_ID)
        :param entry_title: the unique title of the key, which corresponds to the UUID of the device.
        :return: the entry_id name or throws an exception if the operation fails
        """
        self.lte.pppsuspend()
        # see ch 4.1.14 ID and Title (ID shall be fix and title the UUID of the device)

        # prefix public key entry id and public key title with a '_'
        # SS entries must have unique keys and titles
        args = self._encode_tag([(0xC4, str.encode("_" + entry_id)),
                                 (0xC0, binascii.unhexlify(entry_title)),
                                 (0xC1, bytes([0x03])),
                                 (0xC4, str.encode(entry_id)),
                                 (0xC0, binascii.unhexlify(entry_title)),
                                 (0xC1, bytes([0x03]))
                                 ])
        (data, code) = self._execute(STK_APP_KEY_GENERATE.format(int(len(args) / 2), args))
        self.lte.pppresume()
        if code == STK_OK:
            return entry_id
        raise Exception(code)

    def sign(self, entry_id: str, value: bytes, protocol_version: int) -> bytes:
        """
        Sign a message using the given entry_id key.
        :param entry_id: the key to use for signing
        :param value: the message to sign
        :param protocol_version: 0 = regular signing
                                22 = Ubirch Proto v2 signed message
                                23 = Ubirch Proto v2 chained message
        :return: the signature or throws an exceptions if failed
        """
        self.lte.pppsuspend()
        args = self._encode_tag([(0xC4, str.encode(entry_id)), (0xD0, bytes([0x21]))])
        (data, code) = self._execute(STK_APP_SIGN_INIT.format(protocol_version, int(len(args) / 2), args))
        if code == STK_OK:
            args = binascii.hexlify(value).decode()
            # split command into smaller chunks and handle the last chunk differently
            chunk_size = self.MAX_AT_LENGTH - len(STK_APP_SIGN_FINAL)
            chunks = [args[i:i + chunk_size] for i in range(0, len(args), chunk_size)]
            for chunk in chunks[:-1]:
                (data, code) = self._execute(STK_APP_SIGN_FINAL.format(0, int(len(chunk) / 2), chunk))
                if code != STK_OK: break
            else:
                (data, code) = self._execute(STK_APP_SIGN_FINAL.format(1 << 7, int(len(chunks[-1]) / 2), chunks[-1]))
            (data, code) = self._get_response(code)
            self.lte.pppresume()
            if code == STK_OK:
                return data

        self.lte.pppresume()
        raise Exception(code)

    def verify(self, entry_id: str, value: bytes, protocol_version: int) -> bool:
        """
        Verify a signed message using the given entry_id key.
        :param entry_id: the key to use for verification
        :param value: the message to verify
        :param protocol_version: 0 = regular verification
                                22 = Ubirch Proto v2 signed message
                                23 = Ubirch Proto v2 chained message
        :return: the verification response or throws an exceptions if failed
        """
        self.lte.pppsuspend()
        args = self._encode_tag([(0xC4, str.encode('_' + entry_id)), (0xD0, bytes([0x21]))])
        (data, code) = self._execute(STK_APP_VERIFY_INIT.format(protocol_version, int(len(args) / 2), args))
        if code == STK_OK:
            args = binascii.hexlify(value).decode()
            # split command into smaller chunks and handle the last chunk differently
            chunk_size = self.MAX_AT_LENGTH - len(STK_APP_VERIFY_FINAL)
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

    def message_signed(self, name: str, payload: bytes) -> bytes:
        """
        Create a signed ubirch-ubirch message
        :param name: the key entry_id to use for signing
        :param payload: the data to be included in the message
        """
        return self.sign(name, payload, APP_UBIRCH_SIGNED)

    def message_chained(self, name: str, payload: bytes) -> bytes:
        """
        Create a chained ubirch-ubirch message
        :param name: the key entry_id to use for signing
        :param payload: the data to be included in the message
        """
        return self.sign(name, payload, APP_UBIRCH_CHAINED)

    def message_verify(self, name: str, upp: bytes) -> bool:
        """
        Verify a signed ubirch-ubirch message.
        :param name: the name of the key entry_id to use (i.e. a servers public key)
        :param upp: the UPP to verify
        :return: whether the message can be verified
        """
        return self.verify(name, upp, APP_UBIRCH_SIGNED)
