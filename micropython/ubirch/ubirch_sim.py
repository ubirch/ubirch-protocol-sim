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

supported_channels = [0, 1, 2, 3]

# AT+CSIM=LENGTH,COMMAND

# Application Identifier
APP_DF = 'D2760001180002FF34108389C0028B02'

STK_OK = '9000'  # successful command execution
STK_MD = '6310'  # more data, repeat finishing
STK_NF = '6A88'  # not found

# SIM toolkit commands
STK_GET_RESPONSE = '00C00000{:02X}'  # get a pending response
STK_AUTH_PIN = '00200000{:02X}{}'  # authenticate with pin ([1], 2.1.2)
STK_OPEN_CHANNEL = "0070000001"  # open new logical channel to SIM (ISO 7816 part 4 sect. 6.16)
STK_CLOSE_CHANNEL = "007080{:02X}00"  # close a logical channel (ISO 7816 part 4 sect. 6.16)

# generic app commands
STK_APP_SELECT = '00A4040010{}'  # APDU Select Application ([1], 2.1.1)
STK_APP_RANDOM = '80B900{:02X}00'  # APDU Generate Secure Random ([1], 2.1.3)
STK_APP_SS_SELECT = '80A50000{:02X}{}'  # APDU Select SS Entry ([1], 2.1.4)
STK_APP_DELETE_ALL = '80E50000'  # APDU Delete All SS Entries ([1], 2.1.5)
STK_APP_SS_ENTRY_ID_GET = '80B10000{:02X}{}'  # APDU Get SS Entry ID

# ubirch specific commands
STK_APP_SIGN_INIT = '80B5{:02X}00{:02X}{}'  # APDU Sign Init command ([1], 2.2.1)
STK_APP_SIGN_FINAL = '80B6{:02X}00{:02X}{}'  # APDU Sign Update/Final command ([1], 2.2.2)
STK_APP_VERIFY_INIT = '80B7{:02X}00{:02X}{}'  # APDU Verify Signature Init ([1], 2.2.3)
STK_APP_VERIFY_FINAL = '80B8{:02X}00{:02X}{}'  # APDU Verify Signature Update/Final ([1], 2.2.4)

# key management
STK_APP_KEY_GENERATE = '80B28000{:02X}{}'  # APDU Generate Key Pair ([1], 2.1.7)
STK_APP_KEY_STORE = '80D8{:02X}00{:02X}{}'  # store an ECC public key
STK_APP_KEY_GET = '80CB0000{:02X}{}'  # APDU Get Key ([1], 2.1.8)

# certificate management
STK_APP_CSR_GENERATE_FIRST = '80BA{:02X}00{:02X}{}'  # Generate Certificate Sign Request command ([1], 2.1.7)
STK_APP_CSR_GENERATE_NEXT = '80BA810000'  # Get Certificate Sign Request response ([1], 2.1.7)
STK_APP_CERT_STORE = '80E3{:02X}00{:02X}{}'  # Store Certificate ([1], 2.1.9)
STK_APP_CERT_UPDATE = '80E7{:02X}00{:02X}{}'  # Update Certificate ([1], 2.1.10)
STK_APP_CERT_GET = '80CC{:02X}0000'  # Get Certificate ([1], 2.1.11)

APP_UBIRCH_SIGNED = 0x22
APP_UBIRCH_CHAINED = 0x23


def _encode_tag(tags: [(int, bytes or str)]) -> str:
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


def _decode_tag(encoded: bytes) -> [(int, bytes)]:
    """
    Decode APDU response data that contains tags.
    Throws exception if tag decoding fails.
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


class SimProtocol:
    MAX_AT_LENGTH = 110

    def __init__(self, lte: LTE, at_debug: bool = False, channel: int = None):
        """
        Initialize the SIM interface. This executes a command to initialize the modem,
        and waits for the modem to be ready, then selects the SIM application.

        The LTE functionality must be enabled upfront.

        If there is already a channel to the SIM it can be specified with channel=X. Supported
        channel values are 0-3. If not specified a new channel will be requested from the SIM
        and set automatically.
        """
        if channel is not None and channel not in supported_channels:
            raise Exception("unsupported channel: 0x{:X}".format(self._channel))
        self._channel = channel
        self.lte = lte
        self._AT_session_active = False  # wether or not the lib currently opened an AT commands session
        self._AT_session_modem_suspended = False  # wether the modem was suspended for an AT session
        self.DEBUG = at_debug
        self.init()

    def __del__(self):
        self.deinit()

    def init(self):
        self._prepare_AT_session()
        try:
            # make sure we can access the SIM
            if not self._check_sim_access():
                raise Exception("couldn't access SIM")

            # if no channel set: open a new communication channel to SIM and save it
            if self._channel is None:
                self._channel = self._open_channel()

            # select the SIGNiT application
            if not self._select_app():
                raise Exception("selecting SIM application failed")
        finally:
            self._finish_AT_session()

    def deinit(self):
        """
        Deintializes the SIM interface by closing the APDU communication channel. Used
        in preparation for events like low-power sleep or a board reset without a SIM/modem
        reset. Does not deinitialize/disconnect the LTE.
        """
        self._prepare_AT_session()
        try:
            # Close logical channel to SIM if open
            if self._channel is not None and self._channel is not 0:
                self._close_channel(self._channel)
                self._channel = None
        finally:
            self._finish_AT_session()

    def _prepare_AT_session(self):
        """
        Ensures all prerequisites to send AT commands to modem and saves the modems state
        for restoring it later.
        """
        if self._AT_session_active:
            return

        # if modem is connected, suspend it and remember that we did
        if self.lte.isconnected():
            self.lte.pppsuspend()
            self._AT_session_modem_suspended = True

        self._AT_session_active = True

    def _finish_AT_session(self):
        """
        Restores the modem state after the library is finished sending AT commands.
        """
        if not self._AT_session_active:
            return

        # if modem was suspended for the session, restore it
        if self._AT_session_modem_suspended:
            self.lte.pppresume()
            self._AT_session_modem_suspended = False

        self._AT_session_active = False

    def _send_at_cmd(self, cmd):
        if self.DEBUG: print("++ " + cmd)
        result = [k for k in self.lte.send_at_cmd(cmd).split('\r\n') if len(k.strip()) > 0]
        if self.DEBUG: print('-- ' + '\r\n-- '.join([r for r in result]))
        return result

    def _open_channel(self) -> int:
        """
        Open a new logical channel to communicate with the SIM (see ISO 7816 part 4 sect. 6.16)
        Throws an exception if the SIM does not assign a new channel successfully. Returns assigned channel.
        Always uses channel 0 (basic channel) for request. Does not change the internal channel used by the class.
        :return: channel number (assigned by the SIM)
        """
        old_channel = self._channel  # save lib channel
        self._channel = 0  # send on basic channel
        data, code = self._execute(STK_OPEN_CHANNEL)  # send
        self._channel = old_channel  # restore lib channel

        if code != STK_OK or len(data) != 1:
            raise Exception("couldn't open channel, response code: {}, data: {}".format(code, data))

        assigned_channel = int(data[0])
        if assigned_channel not in supported_channels:
            raise Exception("unsupported channel number received")

        return assigned_channel

    def _close_channel(self, channel_to_close: int):
        """
        Closes the specified logical channel to the SIM (see ISO 7816 part 4 sect. 6.16)
        Always uses channel 0 (basic channel) for request. Does not change the internal
        channel used by the class.
        Throws an exception if closing channel failed.
        """
        old_channel = self._channel  # save lib channel
        self._channel = 0  # send on basic channel
        _, code = self._execute(STK_CLOSE_CHANNEL.format(channel_to_close))  # send
        self._channel = old_channel  # restore lib channel

        if code != STK_OK:
            raise Exception("couldn't close channel: {}".format(code))

    def _execute(self, cmd: str) -> (bytes, str):
        """
        Execute an APDU command on the SIM card itself.
        If the APDU contains channel information, encode the channel info into the CLA byte.
        :param cmd: the command to execute
        :return: a tuple of data, code
        """

        # check if this is a command where the CLA byte contains channel info (see ISO 7816 part 4 sect. 5.4.1)
        if cmd[0] in ["0", "8", "A", "9"]:
            # check if valid channel is set
            if self._channel not in supported_channels:
                raise Exception("invalid channel for sending APDU command: {}".format(self._channel))
            # check if APDU command definition indicates non-basic channel or secure messaging
            if cmd[1] != "0":
                raise Exception(
                    "CLA byte (0x{}) of command invalid: indicates specific channel or secure messaging (not supported)".format(
                        cmd[0:2]))
            # encode channel into command
            channel_char = "{!s:.1}".format(self._channel)
            cmd = cmd[0] + channel_char + cmd[2:]

        at_cmd = 'AT+CSIM={},"{}"'.format(len(cmd), cmd.upper())
        result = self._send_at_cmd(at_cmd)

        if result[-1] == 'OK':
            response = result[0][7:].split(',')[1]
            data = b''
            code = response[-4:]
            if len(response) > 4:
                data = binascii.unhexlify(response[0:-4])
            return data, code
        else:
            return b'', result[-1]

    def _send_cmd_in_chunks(self, cmd, args) -> (bytes, str):
        """
        Split command into smaller chunks and handle the last chunk differently
        :return: the data and code response from the last operation
        """
        chunk_size = self.MAX_AT_LENGTH - len(cmd[:-2].format(0, 0))
        chunks = [args[i:i + chunk_size] for i in range(0, len(args), chunk_size)]
        for chunk in chunks[:-1]:
            data, code = self._execute(cmd.format(0, int(len(chunk) / 2), chunk))
            if code != STK_OK:
                return data, code
        else:
            return self._execute(cmd.format(0x80, int(len(chunks[-1]) / 2), chunks[-1]))

    def _get_response(self, code: str) -> (bytes, str):
        """
        Get response from the application.
        :param code: the code response from the previous operation.
        :return: a data, code tuple as a result of APDU GET RESPONSE
        """
        if code[0:2] == '61':
            return self._execute(STK_GET_RESPONSE.format(int(code[2:4], 16)))
        else:
            return b'', "NO RESPONSE DATA ({})".format(code)

    def _get_more_data(self, code: str, data: bytes, cmd: str) -> (bytes, str):
        """
        Append pending data to already retrieved data
        :param code: the code response from the previous operation
        :param data: the data to append more data to
        :param cmd: the command to get the pending data
        :return: a tuple of data, code
        """
        while code == STK_MD:
            more_data, code = self._execute(cmd)
            data += more_data
        return data, code

    def _check_sim_access(self) -> bool:
        """
        Checks Generic SIM Access.
        :return: if SIM access was successful
        """
        for _ in range(3):
            time.sleep(0.2)
            result = self._send_at_cmd("AT+CSIM=?")
            if result[-1] == 'OK':
                return True

        return False

    def _select_app(self) -> bool:
        """
        Select the SIM application to execute secure operations.
        """
        if self.DEBUG: print("\n>> selecting SIM application")
        for _ in range(2):
            time.sleep(0.2)
            data, code = self._execute(STK_APP_SELECT.format(APP_DF))
            if code == STK_OK:
                return True

        return False

    def _select_ss_entry(self, entry_id: str) -> (bytes, str):
        """
        Select an entry from the secure storage of the SIM card
        Throws exception if entry not found or tag decoding fails.
        :param entry_id: the entry ID
        :return: the data and code response from the operation
        """
        data, code = self._execute(STK_APP_SS_SELECT.format(len(entry_id), binascii.hexlify(entry_id).decode()))
        if code == STK_NF:
            raise Exception("entry \"{}\" not found".format(entry_id))

        data, code = self._get_response(code)
        if code == STK_OK and self.DEBUG:
            print('found entry: ' + repr(_decode_tag(data)))
        return data, code

    def sim_auth(self, pin: str):
        """
        Authenticate against the SIM application to be able to use secure operations.
        Throws an exception if PIN not accepted.
        :param pin: the pin to use for authentication
        """
        if self.DEBUG: print("\n>> unlocking SIM")
        self._prepare_AT_session()
        try:
            # FIXME do not print PIN authentication AT command
            data, code = self._execute(STK_AUTH_PIN.format(len(pin), binascii.hexlify(pin).decode()))
        finally:
            self._finish_AT_session()

        if code != STK_OK:
            raise Exception("PIN not accepted: {}".format(code))

    def random(self, length: int) -> bytes:
        """
        Generate random data.
        :param length: the number of random bytes to generate
        :return: a byte array containing the random bytes
        """
        if self.DEBUG: print("\n>> generating random data with length " + str(length))
        self._prepare_AT_session()
        try:
            data, code = self._execute(STK_APP_RANDOM.format(length))
        finally:
            self._finish_AT_session()

        if code == STK_OK:
            return data

        raise Exception(code)

    def erase(self) -> [(int, bytes)]:
        """
        Delete all existing secure memory entries.
        """
        print("\n>> erasing ALL SS entries")
        self._prepare_AT_session()
        try:
            data, code = self._execute(STK_APP_DELETE_ALL)
        finally:
            self._finish_AT_session()

        return data, code

    def entry_exists(self, entry_id: str):
        if self.DEBUG: print("\n>> looking for entry ID \"{}\"".format(entry_id))
        self._prepare_AT_session()
        try:
            _, code = self._execute(STK_APP_SS_SELECT.format(len(entry_id), binascii.hexlify(entry_id).decode()))
        finally:
            self._finish_AT_session()

        if code[0:2] == '61':
            return True
        if code == STK_NF:
            return False

        raise Exception(code)

    def store_public_key(self, entry_id: str, uuid: UUID, pub_key: bytes):
        """
        Store an ECC public key on the SIM cards secure storage
        Throws exception if operation fails.
        :param entry_id: the entry ID for the key to be stored
        :param uuid: the corresponding UUID to the key
        :param pub_key: the key to be stored
        """
        if self.DEBUG: print("\n>> storing public key with entry ID \"{}\"".format(entry_id))

        expected_key_len = 64
        if len(pub_key) != expected_key_len:
            raise Exception(
                "invalid ECC public key length: {}, expected {} bytes".format(len(pub_key), expected_key_len))

        args = _encode_tag([(0xC4, entry_id.encode()),  # Entry ID for public key
                            (0xC0, uuid.hex),  # Entry title (UUID)
                            (0xC1, bytes([0x03])),  # Permission: Read & Write Allowed
                            (0xC2, bytes([0x0B, 0x01, 0x00])),  # TYPE_EC_FP_PUBLIC, LENGTH_EC_FP_256
                            (0xC3, bytes([0x04]) + pub_key)  # Public key to be stored (SEC format)
                            ])
        self._prepare_AT_session()
        try:
            data, code = self._send_cmd_in_chunks(STK_APP_KEY_STORE, args)
        finally:
            self._finish_AT_session()

        if code != STK_OK:
            raise Exception("storing key failed: {}".format(code))

    def get_key(self, entry_id: str) -> bytes:
        """
        Retrieve the public key of a given entry_id.
        :param entry_id: the key to look for
        :return: the public key bytes
        """
        if self.DEBUG: print("\n>> getting public key with entry ID \"{}\"".format(entry_id))
        self._prepare_AT_session()
        try:
            # select SS public key entry
            data, code = self._select_ss_entry(entry_id)
            if code == STK_OK:
                # get the key
                args = _encode_tag([(0xD0, bytes([0x00]))])
                data, code = self._execute(STK_APP_KEY_GET.format(int(len(args) / 2), args))
                data, code = self._get_response(code)
                if code == STK_OK:
                    # remove the fixed 0x04 prefix from the key entry_id
                    return [tag[1][1:] for tag in _decode_tag(data) if tag[0] == 0xc3][0]

            raise Exception(code)
        finally:
            self._finish_AT_session()

    def generate_key(self, entry_id: str, uuid: UUID):
        """
        # FIXME with current pycom FW the AT command for entry titles > 1 byte is too long
        Generate a new key pair and store it on the SIM card using the given entry ID
        and the UUID as entry title.
        Throws an exception if the operation fails.
        :param entry_id: the entry ID of the SS key entry
        :param uuid: the UUID associated with the key
        """
        if self.DEBUG: print("\n>> generating new key pair with entry ID \"{}\"".format(entry_id))
        # see ch 4.1.14 ID and Title (ID shall be fix and title the UUID of the device)

        # prefix private key entry id with a '_'
        # SS entries must have unique entry IDs
        args = _encode_tag([(0xC4, entry_id.encode()),
                            (0xC0, uuid.hex),
                            (0xC1, bytes([0x03])),
                            (0xC4, ("_" + entry_id).encode()),
                            (0xC0, uuid.hex),
                            (0xC1, bytes([0x03]))
                            ])
        self._prepare_AT_session()
        try:
            data, code = self._execute(STK_APP_KEY_GENERATE.format(int(len(args) / 2), args))
        finally:
            self._finish_AT_session()

        if code != STK_OK:
            raise Exception(code)

    def get_entry_title(self, entry_id: str) -> bytes:
        """
        Retrieve the entry title of an entry with a given id.
        :param entry_id: the entry ID of the entry to look for
        :return: the entry title
        """
        if self.DEBUG: print("\n>> getting entry title of entry with ID \"{}\"".format(entry_id))
        self._prepare_AT_session()
        try:
            # select SS entry
            data, code = self._select_ss_entry(entry_id)
        finally:
            self._finish_AT_session()

        if code == STK_OK:
            # get the entry title
            return [tag[1] for tag in _decode_tag(data) if tag[0] == 0xc0][0]

        raise Exception(code)

    def get_uuid(self, entry_id: str) -> UUID:
        """
        Retrieve the UUID associated with a given device name.
        :param entry_id: the entry ID of the SS key entry associated with the UUID
        :return: the UUID
        """
        return UUID(self.get_entry_title(entry_id))

    def generate_csr(self, entry_id: str) -> bytes:
        """
        Request a CSR for the selected key.
        :param entry_id: the entry ID of the SS key entry
        :return: the CSR (bytes)
        """
        if self.DEBUG: print("\n>> generating CSR for key with entry ID \"{}\"".format(entry_id))
        uuid = self.get_uuid(entry_id)

        cert_attr = _encode_tag([
            (0xD4, "DE".encode()),
            (0xD7, "ubirch GmbH".encode()),
            (0xD9, str(uuid).encode()),
        ])
        cert_args = _encode_tag([
            (0xD3, bytes([0x00])),
            (0xE7, cert_attr),
            (0xC2, bytes([0x0B, 0x01, 0x00])),
            (0xD0, bytes([0x21]))
        ])
        args = _encode_tag([
            (0xC4, entry_id.encode()),
            (0xC4, ("_" + entry_id).encode()),
            (0xE5, cert_args)
        ])

        self._prepare_AT_session()
        try:
            _, code = self._send_cmd_in_chunks(STK_APP_CSR_GENERATE_FIRST, args)
            data, code = self._get_response(code)  # get first part of CSR
            data, code = self._get_more_data(code, data, STK_APP_CSR_GENERATE_NEXT)  # get next part of CSR
        finally:
            self._finish_AT_session()

        if code == STK_OK:
            return data

        raise Exception("getting CSR failed: {}".format(code))

    def get_certificate(self, certificate_entry_id: str) -> bytes:
        """
        Retrieve the X.509 certificate with the given entry ID
        :param certificate_entry_id: the entry ID of the SS certificate entry
        :return: the certificate (bytes)
        """
        if self.DEBUG: print("\n>> getting X.509 certificate with entry ID \"{}\"".format(certificate_entry_id))
        self._prepare_AT_session()
        try:
            # select SS certificate entry
            data, code = self._select_ss_entry(certificate_entry_id)
            if code == STK_OK:
                # get the certificate
                data, code = self._execute(STK_APP_CERT_GET.format(0))
                data, code = self._get_more_data(code, data, STK_APP_CERT_GET.format(1))
                if code == STK_OK:
                    return [tag[1] for tag in _decode_tag(data) if tag[0] == 0xc3][0]

            raise Exception(code)
        finally:
            self._finish_AT_session()

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
        if hash_before_sign:
            if self.DEBUG: print(">> data will be hashed by SIM before singing")
            protocol_version |= 0x40  # set flag for automatic hashing
        args = _encode_tag([(0xC4, ('_' + entry_id).encode()), (0xD0, bytes([0x21]))])
        self._prepare_AT_session()
        try:
            _, code = self._execute(STK_APP_SIGN_INIT.format(protocol_version, int(len(args) / 2), args))
            if code == STK_OK:
                args = binascii.hexlify(value).decode()
                _, code = self._send_cmd_in_chunks(STK_APP_SIGN_FINAL, args)
                data, code = self._get_response(code)
                if code == STK_OK:
                    return data

            raise Exception(code)
        finally:
            self._finish_AT_session()

    def verify(self, entry_id: str, value: bytes, protocol_version: int) -> bool:
        """
        Verify a signed message using the given entry_id key.
        :param entry_id: the key to use for verification
        :param value: the message to verify
        :param protocol_version: 0x22 = Ubirch Proto v2 signed message
                                 0x23 = Ubirch Proto v2 chained message
        :return: the verification response or throws an exceptions if failed
        """
        args = _encode_tag([(0xC4, entry_id.encode()), (0xD0, bytes([0x21]))])
        self._prepare_AT_session()
        try:
            _, code = self._execute(STK_APP_VERIFY_INIT.format(protocol_version, int(len(args) / 2), args))
            if code == STK_OK:
                args = binascii.hexlify(value).decode()
                _, code = self._send_cmd_in_chunks(STK_APP_VERIFY_FINAL, args)
                if code == STK_OK:
                    return True
                if code == '6988':
                    return False

            raise Exception(code)
        finally:
            self._finish_AT_session()

    def message_signed(self, name: str, payload: bytes, hash_before_sign: bool = False) -> bytes:
        """
        Create a signed ubirch message (UPP)
        :param name: the key entry_id to use for signing
        :param payload: the data to be included in the message
        :param hash_before_sign: payload will be hashed before it is used to build the UPP
        :return: the signed message or throws an exceptions if failed
        """
        if self.DEBUG: print("\n>> creating signed UPP using key \"_{}\"".format(name))
        return self.sign(name, payload, APP_UBIRCH_SIGNED, hash_before_sign=hash_before_sign)

    def message_chained(self, name: str, payload: bytes, hash_before_sign: bool = False) -> bytes:
        """
        Create a chained ubirch message (UPP)
        :param name: the key entry_id to use for signing
        :param payload: the data to be included in the message
        :param hash_before_sign: payload will be hashed before it is used to build the UPP
        :return: the chained message or throws an exceptions if failed
        """
        if self.DEBUG: print("\n>> creating chained UPP using key \"_{}\"".format(name))
        return self.sign(name, payload, APP_UBIRCH_CHAINED, hash_before_sign=hash_before_sign)

    def message_verify(self, name: str, upp: bytes) -> bool:
        """
        Verify a ubirch protocol message.
        :param name: the name of the key entry_id to use (i.e. a servers public key)
        :param upp: the UPP to verify
        :return: whether the message can be verified
        """
        if upp[1] == APP_UBIRCH_SIGNED:
            if self.DEBUG: print("\n>> verifying signed UPP using key \"{}\"".format(name))
            return self.verify(name, upp, APP_UBIRCH_SIGNED)
        elif upp[1] == APP_UBIRCH_CHAINED:
            if self.DEBUG: print("\n>> verifying chained UPP using key \"{}\"".format(name))
            return self.verify(name, upp, APP_UBIRCH_CHAINED)
        else:
            raise Exception("message is not a UPP")
