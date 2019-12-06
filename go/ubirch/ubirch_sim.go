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
	stkAuthPin     = "00200000%02X%s" // authenticate with pin

	// Generic app commands
	stkAppSelect    = "00A4040010%s"   // APDU Select Application
	stkAppRandom    = "80B900%02X00"   // APDU Generate Secure Random ([1], 4.2.7, page 50)
	stkAppDeleteAll = "80E50000"       // APDU Delete All SS Entries ([1], 4.1.7, page 30)
	stkAppSsSelect  = "80A50000%02X%s" // APDU Select SS Entry ([1], 4.1.2, page 25)

	// Ubirch ubirch specific commands
	stkAppKeyGenerate = "80B28000%02X%s"   // APDU Generate Key Pair
	stkAppKeyGet      = "80CB0000%02X%s"   // APDU Get Key
	stkAppSignInit    = "80B5%02X00%02X%s" // APDU Sign Init command ([1], page 14)
	stkAppSignFinal   = "80B6%02X00%02X%s" // APDU Sign Update/Final command ([1], page 15)
	stkAppVerifyInit  = "80B7%02X00%02X%s" // APDU Verify Signature Init ([1], page 11)
	stkAppVerifyFinal = "80B8%02X00%02X%s" // APDU Verify Signature Update/Final ([1], page 12)

	// Certificate management
	stkAppCsrGenerate = "80BA%02X00%02X%s" // Generate Certificate Sign Request command ([1], page 5)

)

// encode Tags into a hex encoded string.
func (p *Protocol) encodeBinary(tags []Tag) []byte {
	var e []byte
	for _, tag := range tags {
		if p.Debug {
			log.Printf("ENC tag=0x%02x, len=%3d, data=%s [%q]\n", tag.Tag, len(tag.Data), hex.EncodeToString(tag.Data), tag.Data)
		}
		e = append(e, tag.Tag, byte(len(tag.Data)))
		e = append(e, tag.Data...)
	}
	return e
}

// encode Tags into a hex encoded string.
func (p *Protocol) encode(tags []Tag) string {
	return strings.ToUpper(hex.EncodeToString(p.encodeBinary(tags)))
}

func (p *Protocol) decodeBinary(bin []byte) ([]Tag, error) {
	var tags []Tag
	for i := 0; i < len(bin); i++ {
		if len(bin) < i+2 {
			return nil, errors.New(fmt.Sprintf("missing tag length: %s", hex.EncodeToString(bin[i:])))
		}
		tag := bin[i]
		tagLen := int(bin[i+1])
		if len(bin)-2 < tagLen {
			return nil, errors.New(fmt.Sprintf("tag %02x has not enough data %d < %d", tag, len(bin)-2, tagLen))
		}
		if p.Debug {
			log.Printf("DEC tag=0x%02x, len=%3d [%02x], data=%s [%q]\n", tag, tagLen, bin[i+1], hex.EncodeToString(bin[i+2:i+2+tagLen]), bin[i+2:i+2+tagLen])
		}
		tags = append(tags, Tag{tag, bin[i+2 : i+2+tagLen]})
		i += 1 + tagLen
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
func (p *Protocol) execute(format string, v ...interface{}) (string, int, error) {
	cmd := fmt.Sprintf(format, v...)
	atcmd := fmt.Sprintf("AT+CSIM=%d,\"%s\"", len(cmd), cmd)
	response, err := p.Send(atcmd)
	if err != nil {
		return "", 0, err
	}
	if response[len(response)-1] == "OK" {
		responseLength := 0
		responseData := ""
		responseCode := ApduOk

		_, err := fmt.Sscanf(response[0], "+CSIM: %d,%s", &responseLength, &responseData)
		if err != nil {
			return "", 0, err
		}
		if responseLength != len(responseData) {
			return "", 0, errors.New("response length does not match data size")
		}

		if responseLength >= 4 && len(responseData) >= 4 {
			codeIndex := len(responseData) - 4
			code, err := strconv.ParseUint(responseData[codeIndex:], 16, 16)
			if err != nil {
				return "", 0, errors.New(fmt.Sprintf("invalid response code '%s': %s", responseData[codeIndex:], err))
			}
			responseData, responseCode = responseData[0:codeIndex], int(code)
		}
		return responseData, responseCode, err
	} else {
		return "", 0, errors.New(fmt.Sprintf("error executing modem command: %s", response[len(response)-1]))
	}
}

// retrieve an extended response by executing the get response APDU command
func (p *Protocol) response(code int) (string, error) {
	c := code >> 8
	l := code & 0xff
	data := ""
	for c == 0x61 || c == 0x63 {
		r, code, err := p.execute(stkGetResponse, l)
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
		{0xC4, []byte("_" + name)},
		{0xC0, uidBytes},
		{0xC1, []byte{0x02}},
		{0xC4, []byte(name)},
		{0xC0, uidBytes},
		{0xC1, []byte{0x02}},
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
		{0xD3, []byte{0x00}},
		{0xE7, certAttributes},
		{0xC2, []byte{0x0B, 0x01, 0x00}},
		{0xD0, []byte{0x21}},
	})

	args := p.encode([]Tag{
		{0xC4, []byte(name)},
		{0xC4, []byte("_" + name)},
		{0xE5, certArgs},
	})

	_, code, err := p.execute(stkAppCsrGenerate, 0x80, len(args)/2, args)
	if err != nil {
		return nil, err
	}
	if code != 0x6100 {
		return nil, errors.New(fmt.Sprintf("unable to generate certificate signing request: 0x%x", code))
	}

	data, err := p.response(code)
	if err != nil {
		return nil, err
	}

	return hex.DecodeString(data)
}

// Get the public key for a given name from the SIM storage.
// Returns a byte array with the raw bytes of the public key.
func (p *Protocol) GetKey(name string) ([]byte, error) {
	name = "_" + name
	_, code, err := p.execute(stkAppSsSelect, len(name), hex.EncodeToString([]byte(name)))
	if err != nil {
		return nil, err
	}
	_, err = p.response(code)
	if err != nil {
		return nil, err
	}

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
func (p *Protocol) Sign(name string, value []byte, protocol int) ([]byte, error) {
	args := p.encode([]Tag{
		{0xc4, []byte(name)},
		{0xd0, []byte{0x21}},
	})
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
func (p *Protocol) Verify(name string, value []byte, protocol int) (bool, error) {
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
