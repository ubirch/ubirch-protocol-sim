package ubirch

import (
	"errors"
	"fmt"
	"github.com/google/uuid"
	"log"
	"strconv"
	"strings"
)
import "encoding/hex"

type SimInterface interface {
	Send(cmd string) ([]string, error)
}

type Protocol struct {
	SimInterface
	Debug bool
}

type Tag struct {
	Tag  byte
	Data []byte
}

//noinspection GoUnusedConst
const (
	Signed  = 0x22
	Chained = 0x23

	// APDU response codes
	ApduOk       = 0x9000
	ApduMoreData = 0x6310

	// Application Identifier
	stkAppDef = "D2760001180002FF34108389C0028B02"

	// SIM toolkit commands
	stkGetResponse = "00C00000%02X"   // get a pending response
	stkAuthPin     = "00200000%02X%s" // authenticate with pin ([1], 2.1.2)

	// Generic app commands
	stkAppSelect        = "00A4040010%s"   // APDU Select Application ([1], 2.1.1)
	stkAppRandom        = "80B900%02X00"   // APDU Generate Secure Random ([1], 2.1.3)
	stkAppSsEntrySelect = "80A50000%02X%s" // APDU Select SS Entry ([1], 2.1.4)
	stkAppDeleteAll     = "80E50000"       // APDU Delete All SS Entries

	// Ubirch specific commands
	stkAppKeyGenerate = "80B28000%02X%s"   // APDU Generate Key Pair ([1], 2.1.7)
	stkAppKeyGet      = "80CB0000%02X%s"   // APDU Get Key ([1], 2.1.9)
	stkAppSignInit    = "80B5%02X00%02X%s" // APDU Sign Init command ([1], 2.2.1)
	stkAppSignFinal   = "80B6%02X00%02X%s" // APDU Sign Update/Final command ([1], 2.2.2)
	stkAppVerifyInit  = "80B7%02X00%02X%s" // APDU Verify Signature Init ([1], 2.2.3)
	stkAppVerifyFinal = "80B8%02X00%02X%s" // APDU Verify Signature Update/Final ([1], 2.2.4)

	// Certificate management
	stkAppCsrGenerateFirst = "80BA8000%02X%s" // Generate Certificate Sign Request command ([1], 2.1.8)
	stkAppCsrGenerateNext  = "80BA8100%02X"   // Get Certificate Sign Request response ([1], 2.1.8)
)

// encode Tags into binary format (1 byte tag + 1 byte len + len bytes data)
func (p *Protocol) encodeBinary(tags []Tag) []byte {
	var encoded []byte
	for _, tag := range tags {
		if p.Debug {
			log.Printf("ENC tag=0x%02x, len=%3d, data=%s [%q]\n", tag.Tag, len(tag.Data), hex.EncodeToString(tag.Data), tag.Data)
		}
		encoded = append(encoded, tag.Tag, byte(len(tag.Data)))
		encoded = append(encoded, tag.Data...)
	}
	return encoded
}

// encode Tags into a hex encoded string.
func (p *Protocol) encode(tags []Tag) string {
	return strings.ToUpper(hex.EncodeToString(p.encodeBinary(tags)))
}

// decode Tags from binary format.
func (p *Protocol) decodeBinary(bin []byte) ([]Tag, error) {
	var tags []Tag
	var tagLen int
	for i := 0; i < len(bin); i += 2 + tagLen {
		if len(bin) < i+2 {
			return nil, errors.New(fmt.Sprintf("missing tag length: %s", hex.EncodeToString(bin[i:])))
		}
		tag := bin[i]
		tagLen = int(bin[i+1])
		if len(bin[i+2:]) < tagLen {
			return nil, errors.New(fmt.Sprintf("tag %02x has not enough data %d < %d", tag, len(bin[i+2:]), tagLen))
		}
		if p.Debug {
			log.Printf("DEC tag=0x%02x, len=%3d [%02x], data=%s [%q]\n", tag, tagLen, bin[i+1], hex.EncodeToString(bin[i+2:i+2+tagLen]), bin[i+2:i+2+tagLen])
		}
		tags = append(tags, Tag{tag, bin[i+2 : i+2+tagLen]})
	}
	return tags, nil
}

// decode a hex encoded string into Tags.
func (p *Protocol) decode(s string, debug ...bool) ([]Tag, error) {
	bin, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return p.decodeBinary(bin)
}

// executes an APDU command and returns the response
func (p *Protocol) execute(format string, v ...interface{}) (string, uint16, error) {
	cmd := fmt.Sprintf(format, v...)
	atcmd := fmt.Sprintf("AT+CSIM=%d,\"%s\"", len(cmd), cmd)
	response, err := p.Send(atcmd)
	if err != nil {
		return "", 0, err
	}
	if response[len(response)-1] == "OK" {
		responseLength := 0
		responseData := ""
		responseCode := uint16(ApduOk)

		_, err := fmt.Sscanf(response[0], "+CSIM: %d,%s", &responseLength, &responseData)
		if err != nil {
			return "", 0, err
		}
		if responseLength != len(responseData) {
			return "", 0, errors.New("response length does not match data size")
		}

		if responseLength >= 4 {
			codeIndex := responseLength - 4
			code, err := strconv.ParseUint(responseData[codeIndex:], 16, 16)
			if err != nil {
				return "", 0, errors.New(fmt.Sprintf("invalid response code '%s': %s", responseData[codeIndex:], err))
			}
			responseData, responseCode = responseData[0:codeIndex], uint16(code)
		}
		return responseData, responseCode, err
	} else {
		return "", 0, errors.New(fmt.Sprintf("error executing modem command: %s", response[len(response)-1]))
	}
}

// retrieve an extended response by executing the get response APDU command
func (p *Protocol) response(code uint16) (string, error) {
	c := code >> 8   // first byte -> response code: 0x61 or 0x63 indicate that there is more data available
	l := code & 0xff // second byte -> length of available data
	data := ""
	if c == 0x61 || c == 0x63 { // check if more data available
		r, code, err := p.execute(stkGetResponse, l) // request available data
		if err != nil {
			return "", err
		}
		c = code >> 8
		l = code & 0xff
		data += r
	}
	return data, nil
}

func (p *Protocol) selectApplet() error {
	if p.Debug {
		log.Println("SIM applet select")
	}
	_, code, err := p.execute(stkAppSelect, stkAppDef)
	if err != nil {
		return err
	}
	if code != ApduOk {
		return errors.New(fmt.Sprintf("APDU error: %x, select failed", code))
	}
	return nil
}

func (p *Protocol) authenticate(pin string) error {
	if p.Debug {
		log.Println("SIM authenticating")
	}
	_, code, err := p.execute(stkAuthPin, len(pin), hex.EncodeToString([]byte(pin)))
	if err != nil {
		return err
	}
	if code != ApduOk {
		return errors.New(fmt.Sprintf("APDU error: %x, pin auth failed", code))
	}
	return nil
}

// Initialize the SIM card application by authenticating with the SIM with the given pin.
func (p *Protocol) Init(pin string) error {
	err := p.selectApplet()
	if err != nil {
		return err
	}

	return p.authenticate(pin)
}

// Delete all SSEntries on the SIM card, effectively erasing all stored keys.
// This may not work, depending on the application settings.
func (p *Protocol) DeleteAll() error {
	_, code, err := p.execute(stkAppDeleteAll)
	if err != nil {
		return err
	}
	if code != ApduOk {
		return errors.New(fmt.Sprintf("APDU error: %x, delete failed", code))
	}
	return err
}

// Generate a random number of bytes using the SIM cards cryptographic rnd.
// The length of the byte array is determined by the length parameter.
func (p *Protocol) Random(len int) ([]byte, error) {
	r, code, err := p.execute(stkAppRandom, len)
	if err != nil {
		return nil, err
	}
	if code != ApduOk {
		return nil, errors.New(fmt.Sprintf("APDU error: %x, generate random failed", code))
	}
	return hex.DecodeString(r)
}

// Generate a key pair on the SIM card and store it using the given name and the UUID that is
// later used for the ubirch-protocol. The name for public keys is prefixed with an underscore
// ("_") and the private key gets the name as is. This API automatically selects the right name.
func (p *Protocol) GenerateKey(name string, uid uuid.UUID) error {
	uidBytes, err := uid.MarshalBinary()
	if err != nil {
		return err
	}

	args := p.encode([]Tag{
		{0xC4, []byte("_" + name)}, // Entry ID (public key))
		{0xC0, uidBytes},           // Entry title
		{0xC1, []byte{0x03}},       // Permission: Read & Write Allowed
		{0xC4, []byte(name)},       // Entry ID (private key))
		{0xC0, uidBytes},           // Entry title
		{0xC1, []byte{0x02}},       // Permission: Only Write Allowed
	})
	_, code, err := p.execute(stkAppKeyGenerate, len(args)/2, args)
	if err != nil {
		return err
	}
	if code != ApduOk {
		return errors.New(fmt.Sprintf("APDU error: %x, generate key failed", code))
	}
	return err
}

func (p *Protocol) GetCSR(name string) ([]byte, error) {
	certAttributes := p.encodeBinary([]Tag{
		{0xD4, []byte("DE")},
		{0xD5, []byte("Berlin")},
		{0xD6, []byte("Berlin")},
		{0xD7, []byte("ubirch GmbH")},
		{0xD8, []byte("Security")},
		{0xD9, []byte("ubirch.com")},
		{0xDA, []byte("info@ubirch.com")},
	})
	certArgs := p.encodeBinary([]Tag{
		{0xD3, []byte{0x00}},             // Version
		{0xE7, certAttributes},           // Subject Information
		{0xC2, []byte{0x0B, 0x01, 0x00}}, // Subject PKI Algorithm Identifier: Key Type: TYPE_EC_FP_PUBLIC, Key Length: LENGTH_EC_FP_256
		{0xD0, []byte{0x21}},             // Signature Algorithm Identifier: ALG_ECDSA_SHA_256
	})

	args := p.encode([]Tag{
		{0xC4, []byte("_" + name)}, // Public Key ID of the key to be used as the Public Key carried in the CSR
		{0xC4, []byte(name)},       // Private Key ID of the key to be used for signing the CSR
		{0xE5, certArgs},           // Certification Request parameters
	})

	_, code, err := p.execute(stkAppCsrGenerateFirst, len(args)/2, args) // Generate CSR (Last block – get first)
	if err != nil {
		return nil, err
	}
	if code != 0x6100 {
		return nil, errors.New(fmt.Sprintf("unable to generate certificate signing request: 0x%x", code))
	}

	data, code, err := p.execute(stkGetResponse, 0x00) // get response
	if err != nil {
		return nil, err
	}

	rest := ""
	if code == ApduMoreData {
		rest, code, _ = p.execute(stkAppCsrGenerateNext, 0x00) // Generate CSR (Last block – get next) - Wrong length
		c := code >> 8
		l := code & 0xff
		if c == 0x6C {
			rest, code, _ = p.execute(stkAppCsrGenerateNext, l) // Generate CSR (Last block – get next) - actual length
		}
	}
	data += rest

	return hex.DecodeString(data)
}

// Get the public key for a given name from the SIM storage.
// Returns a byte array with the raw bytes of the public key.
func (p *Protocol) GetKey(name string) ([]byte, error) {
	// select SS entry
	name = "_" + name
	_, code, err := p.execute(stkAppSsEntrySelect, len(name), hex.EncodeToString([]byte(name)))
	if err != nil {
		return nil, err
	}
	_, err = p.response(code)
	if err != nil {
		return nil, err
	}

	// get public key from selected entry
	args := p.encode([]Tag{{0xd0, []byte{0x00}}})
	_, code, err = p.execute(stkAppKeyGet, len(args)/2, args)
	if err != nil {
		return nil, err
	}

	data, err := p.response(code)
	if err != nil {
		return nil, err
	}
	tags, err := p.decode(data)
	if err != nil {
		return nil, err
	}
	for _, tag := range tags {
		if tag.Tag == 0xc3 {
			// return the public key and remove the static 0xc4 from the beginning
			return tag.Data[1:], nil
		}
	}
	return nil, errors.New("did not find public key entry, no tag 0xc3")
}

// Execute a sign operation using the key selected by the given name. Depending on
// the protocol parameter the sign operation creates a signed or chained ubirch-protocol
// packet (UPP). If the protocol parameter is 0 a normal signing operation on the
// pure value data is executed.
// The method returns the signed data in the form of a ubirch-protocol packet (UPP) or
// the raw signature in case protocol is 0.
func (p *Protocol) Sign(name string, value []byte, protocol byte, hashBeforeSign bool) ([]byte, error) {
	args := p.encode([]Tag{
		{0xc4, []byte(name)}, // Entry ID
		{0xd0, []byte{0x21}}, // Algorithm to be used: ALG_ECDSA_SHA_256
	})
	if hashBeforeSign {
		protocol |= 0x40 // set flag for automatic hashing
	}
	_, code, err := p.execute(stkAppSignInit, protocol, len(args)/2, args)
	if err != nil {
		return nil, err
	}
	if code != ApduOk {
		return nil, errors.New(fmt.Sprintf("sign init failed: %v", err))
	}

	data := hex.EncodeToString(value)
	for finalBit := 0; len(data) > 0; {
		end := 128
		if len(data) < 128 {
			finalBit = 1 << 7
			end = len(data)
		}
		chunk := data[:end]
		_, code, err = p.execute(stkAppSignFinal, finalBit, len(chunk)/2, chunk)
		if err != nil {
			return nil, err
		}
		if code != ApduOk {
			break
		}
		data = data[end:]
	}

	data, err = p.response(code)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(data)
}

// Execute a verify operation using the public key with the given name. Depending on
// the protocol parameter the verify operation checks a signed or chained ubirch-protocol
// packet (UPP). If the protocol parameter is 0 a normal verify operation on the
// pure value data is executed.
// Returns true or false.
func (p *Protocol) Verify(name string, value []byte, protocol byte) (bool, error) {
	args := p.encode([]Tag{
		{0xc4, []byte("_" + name)},
		{0xd0, []byte{0x21}},
	})
	_, code, err := p.execute(stkAppVerifyInit, protocol, len(args)/2, args)
	if err != nil {
		return false, err
	}
	if code != ApduOk {
		return false, errors.New(fmt.Sprintf("verify init failed: %v", err))
	}

	data := hex.EncodeToString(value)
	for finalBit := 0; len(data) > 0; {
		end := 128
		if len(data) < 128 {
			finalBit = 1 << 7
			end = len(data)
		}
		chunk := data[:end]
		_, code, err = p.execute(stkAppVerifyFinal, finalBit, len(chunk)/2, chunk)
		if err != nil {
			return false, err
		}
		if code != ApduOk {
			return false, nil
		}
		data = data[end:]
	}

	return true, nil
}
