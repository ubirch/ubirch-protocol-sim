package ubirch

// [1]: "../../SIGNiT Customer Manual v4.pdf"

import (
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

type SimInterface interface {
	Send(cmd string) ([]string, error)
	Close() error
}

type Protocol struct {
	SimInterface
	Debug bool
}

type Tag struct {
	Tag  byte
	Data []byte
}

// ProtocolType definition
type ProtocolType byte

//noinspection GoUnusedConst
const (
	//constants for number of bytes used for parameters of NIST P-256 curve
	nistp256PrivkeyLength   = 32                                //Bytes
	nistp256XLength         = 32                                //Bytes
	nistp256YLength         = 32                                //Bytes
	nistp256PubkeyLength    = nistp256XLength + nistp256YLength //Bytes, Pubkey = concatenate(X,Y)
	nistp256RLength         = 32                                //Bytes
	nistp256SLength         = 32                                //Bytes
	nistp256SignatureLength = nistp256RLength + nistp256SLength //Bytes, Signature = concatenate(R,S)
)
const (
	Plain   ProtocolType = 0x00 // Plain signature
	Signed  ProtocolType = 0x22 // Signed UBIRCH protocol package
	Chained ProtocolType = 0x23 // Chained UBIRCH protocol package

	// APDU response codes
	ApduOk                 = uint16(0x9000)
	ApduMoreData           = uint16(0x6310)
	ApduNotFound           = uint16(0x6A88)
	ApduWrongData          = uint16(0x6A80)
	ApduIncorrectSignature = uint16(0x6988)

	// Application Identifier
	stkAppDef = "D2760001180002FF34108389C0028B02"

	// SIM toolkit commands
	stkGetResponse = "00C00000%02X"   // get a pending response
	stkAuthPin     = "00200000%02X%s" // authenticate with pin ([1], 2.1.2)

	// Generic app commands
	stkAppSelect             = "00A4040010%s"   // APDU Select Application ([1], 2.1.1)
	stkAppRandom             = "80B900%02X00"   // APDU Generate Secure Random ([1], 2.1.3)
	stkAppSsEntrySelect      = "80A50000%02X%s" // APDU Select SS Entry ([1], 2.1.4)
	stkAppSsEntrySelectFirst = "80A5010000"     // APDU Select First SS Entry ([1], 2.1.4)
	stkAppSsEntrySelectNext  = "80A5020000"     // APDU Select Next SS Entry ([1], 2.1.4)
	stkAppDeleteAll          = "80E50000"       // APDU Delete All SS Entries
	stkAppSsDeleteEntryID    = "80E40000%02X%s" // APDU Delete SS Entry ([1], 2.1.5)
	stkAppSsEntryIdGet       = "80B10000%02X%s" // APDU Get SS Entry ID

	// Ubirch specific commands
	stkAppKeyGenerate = "80B28000%02X%s"   // APDU Generate an ECC Key Pair ([1], 2.1.7)
	stkAppKeyGet      = "80CB0000%02X%s"   // APDU Get Key ([1], 2.1.9)
	stkAppKeyPut      = "80D88000%02X%s"   // APDU Store an ECC public key
	stkAppSignInit    = "80B5%02X00%02X%s" // APDU Sign Init command ([1], 2.2.1)
	stkAppSignFinal   = "80B6%02X00%02X%s" // APDU Sign Update/Final command ([1], 2.2.2)
	stkAppVerifyInit  = "80B7%02X00%02X%s" // APDU Verify Signature Init ([1], 2.2.3)
	stkAppVerifyFinal = "80B8%02X00%02X%s" // APDU Verify Signature Update/Final ([1], 2.2.4)

	// Certificate management
	stkAppCsrGenerateFirst = "80BA8000%02X%s"   // Generate Certificate Sign Request command ([1], 2.1.8)
	stkAppCsrGenerateNext  = "80BA8100%02X"     // Get Certificate Sign Request response ([1], 2.1.8)
	stkAppCertStore        = "80E3%02X00%02X%s" // Store Certificate
	stkAppCertUpdate       = "80E7%02X00%02X%s" // Update Certificate
	stkAppCertGet          = "80CC%02X0000"     // Get Certificate
)

// encode Tags into binary format
func (p *Protocol) encodeBinary(tags []Tag) ([]byte, error) {
	var encoded []byte
	for _, tag := range tags {
		if p.Debug {
			log.Printf("ENC tag=0x%02x, len=%3d [%02x], data=%s [%q]\n", tag.Tag, len(tag.Data), len(tag.Data), hex.EncodeToString(tag.Data), tag.Data)
		}

		encoded = append(encoded, tag.Tag)
		length := len(tag.Data)
		if length <= 0xff {
			encoded = append(encoded, byte(length))
		} else if length <= 0xffff {
			lenBuf := make([]byte, 3)
			lenBuf[0] = byte(0x82) // 0x82 indicates the length of the tag data being 2 bytes long)
			lenBuf[1] = byte(length >> 8)
			lenBuf[2] = byte(length)
			encoded = append(encoded, lenBuf...)
		} else {
			return nil, fmt.Errorf("tag data len exceeds max len of 65,535 (0xffff) bytes")
		}
		encoded = append(encoded, tag.Data...)
	}
	return encoded, nil
}

// encode Tags into a hex encoded string.
func (p *Protocol) encode(tags []Tag) (string, error) {
	binary, err := p.encodeBinary(tags)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(binary)), nil
}

// decode Tags from binary format.
func (p *Protocol) decodeBinary(bin []byte) ([]Tag, error) {
	var tags []Tag
	var tagLen int
	for i := 0; i < len(bin); i += 2 + tagLen {
		if len(bin) < i+2 {
			return nil, fmt.Errorf("missing tag length: %s", hex.EncodeToString(bin[i:]))
		}
		tag := bin[i]
		tagLen = int(bin[i+1])
		if tagLen == 0x82 { // 0x82 indicates the length of the tag data being 2 bytes long
			tagLen = int(bin[i+2])<<8 | int(bin[i+3])
			i += 2
		}
		if len(bin[i+2:]) < tagLen {
			return nil, fmt.Errorf("tag %02x has not enough data %d < %d", tag, len(bin[i+2:]), tagLen)
		}
		if p.Debug {
			log.Printf("DEC tag=0x%02x, len=%3d [%02x], data=%s [%q]\n", tag, tagLen, tagLen, hex.EncodeToString(bin[i+2:i+2+tagLen]), bin[i+2:i+2+tagLen])
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
				return "", 0, fmt.Errorf("invalid response code '%s': %s", responseData[codeIndex:], err)
			}
			responseData, responseCode = responseData[0:codeIndex], uint16(code)
		}
		return responseData, responseCode, err
	} else {
		return "", 0, fmt.Errorf("error executing modem command: %s", response[len(response)-1])
	}
}

// retrieve an extended response by executing the get response APDU command
func (p *Protocol) response(code uint16) (string, uint16, error) {
	c := code >> 8   // first byte -> response code: 0x61 indicate that there is more data available
	l := code & 0xff // second byte -> length of available data
	data := ""
	for c == 0x61 { // check if more data available
		r := ""
		var err error // avoid shadowing of 'code'
		if p.Debug {
			log.Printf(">> get response")
		}
		r, code, err = p.execute(stkGetResponse, l) // request available data
		if err != nil {
			return "", 0, err
		}
		c = code >> 8
		l = code & 0xff
		data += r
	}
	if data == "" {
		return data, code, fmt.Errorf("no response data")
	}
	return data, code, nil
}

func (p *Protocol) findTag(tags []Tag, tagID byte) ([]byte, error) {
	for _, tag := range tags {
		if tag.Tag == tagID {
			return tag.Data, nil
		}
	}
	return nil, fmt.Errorf("did not find tag %x", tagID)
}

func (p *Protocol) selectApplet() error {
	if p.Debug {
		log.Println(">> select SIM applet")
	}
	_, code, err := p.execute(stkAppSelect, stkAppDef)
	if err != nil {
		return err
	}
	if code != ApduOk {
		return fmt.Errorf("APDU error: %x, select failed", code)
	}
	return nil
}

func (p *Protocol) authenticate(pin string) error {
	if p.Debug {
		log.Println(">> authenticate")
	}
	_, code, err := p.execute(stkAuthPin, len(pin), hex.EncodeToString([]byte(pin)))
	if err != nil {
		return err
	}
	if code != ApduOk {
		return fmt.Errorf("APDU error: %x, pin auth failed", code)
	}
	return nil
}

// Initialize the SIM card application by authenticating with the SIM with the given pin.
func (p *Protocol) Init(pin string) error {
	var err error
	// sometimes the modem is not ready yet, so we try again, if it fails
	for i := 0; i < 3; i++ {
		err = p.selectApplet()
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	return p.authenticate(pin)
}

// selectSSEntryID selects an entry in the secure storage using the entry ID, see [1] 2.1.4
// returns the entry title (usually UUID) sent by the SIM as response to the command as well as the APDU code and error condition
//also checks if selected entry ID is the same as in the request
func (p *Protocol) selectSSEntryID(entryID string) ([]byte, uint16, error) {
	if p.Debug {
		log.Printf(">> selecting SS entry \"%s\"", entryID)
	}
	// select SS entry
	_, code, err := p.execute(stkAppSsEntrySelect, len(entryID), hex.EncodeToString([]byte(entryID)))
	if err != nil {
		return nil, code, err
	}
	if code == ApduNotFound {
		return nil, code, fmt.Errorf("entry \"%s\" not found", entryID)
	}
	data, code, err := p.response(code)
	if err != nil {
		return nil, code, err
	}
	if code != ApduOk {
		return nil, code, fmt.Errorf("APDU error code: %x, selecting SS entry (%s) failed", code, entryID)
	}

	// get entry title and also check returned entry ID for consistency with request
	tags, err := p.decode(data)
	if err != nil {
		return nil, code, err
	}
	entryIDreturned, err := p.findTag(tags, byte(0xc4))
	if err != nil {
		return nil, code, err
	}
	if string(entryIDreturned) != entryID {
		return nil, code, fmt.Errorf("selected entry ID is not the same as the requested entry ID: %v != %v", string(entryIDreturned), entryID)
	}

	entryTitle, err := p.findTag(tags, byte(0xc0))
	if err != nil {
		return nil, code, err
	}

	return entryTitle, code, nil
}

// GetAllSSEntries gets IDs and titles of all SS entries present on the SIM, this includes keys and certificates
func (p *Protocol) GetAllSSEntries() ([]map[string]string, error) {
	if p.Debug {
		log.Printf(">> get all SS entries")
	}
	entryMap := []map[string]string{}
	currEntry := 0
	selectCommand := stkAppSsEntrySelectFirst
	done := false

	for !done {
		//select which command to use based on start or continuation of the selection process
		if currEntry == 0 {
			selectCommand = stkAppSsEntrySelectFirst
		} else {
			selectCommand = stkAppSsEntrySelectNext
		}
		// select first/next SS entry
		resp, code, err := p.execute(selectCommand)
		if err != nil {
			return nil, err
		}
		//check if an entry was found
		if code == ApduOk { //if found: decode, save data to map
			tags, err := p.decode(resp)
			if err != nil {
				return nil, err
			}
			entryID, err := p.findTag(tags, 0xc4) //entry ID (mandatory)
			if err != nil {
				return nil, err
			}
			entryMap = append(entryMap, map[string]string{}) //add empty map for this entry
			entryMap[currEntry]["entryID"] = string(entryID) //save to map

			entryTitle, err := p.findTag(tags, 0xc0) //entry title (mandatory, but might be "")
			if err != nil {
				return nil, err
			}
			entryMap[currEntry]["entryTitle"] = string(entryTitle) //save to map
			currEntry++
		} else if code == ApduNotFound {
			//we tried to  select next entry, but where already at the last one -> we're done
			done = true
		} else { //something unexpected was returned
			return nil, fmt.Errorf("APDU error, response code was %x", code)
		}
	}
	return entryMap, nil
}

//DeleteSSEntryID deletes an entry in the secure storage (SS) of the SIM using it's entry ID
//It returns the response code and the error condition. The code can be used to unambigously check
//the cause of the error in the caller.
func (p *Protocol) DeleteSSEntryID(entryID string) (uint16, error) {
	if p.Debug {
		log.Printf(">> deleting SS entry \"%s\"", entryID)
	}
	// delete SS entry command
	_, code, err := p.execute(stkAppSsDeleteEntryID, len(entryID), hex.EncodeToString([]byte(entryID)))
	if err != nil {
		return code, err
	}

	switch code {
	case ApduOk:
		return code, nil
	case ApduNotFound:
		return code, fmt.Errorf("entry \"%s\" not found", entryID)
	case ApduWrongData:
		return code, fmt.Errorf("invalid entry ID length")
	default:
		return code, fmt.Errorf("unexpected return code received")
	}
}

// Delete all SSEntries on the SIM card, effectively erasing all stored keys.
// This may not work, depending on the application settings.
func (p *Protocol) DeleteAll() error {
	if p.Debug {
		log.Println(">> delete ALL SS entries")
	}
	_, code, err := p.execute(stkAppDeleteAll)
	if err != nil {
		return err
	}
	if code != ApduOk {
		return fmt.Errorf("APDU error: %x, delete failed", code)
	}
	return err
}

// Generate a random number of bytes using the SIM cards cryptographic rnd.
// The length of the byte array is determined by the length parameter.
func (p *Protocol) Random(len int) ([]byte, error) {
	if p.Debug {
		log.Printf(">> generate random number (%d bytes)", len)
	}
	r, code, err := p.execute(stkAppRandom, len)
	if err != nil {
		return nil, err
	}
	if code != ApduOk {
		return nil, fmt.Errorf("APDU error: %x, generate random failed", code)
	}
	return hex.DecodeString(r)
}

func (p *Protocol) GetIMSI() (string, error) {
	if p.Debug {
		log.Println(">> get IMSI")
	}
	const IMSI_LEN = 15
	var imsi string
	var err error
	// sometimes the modem is not ready to retrieve the IMSI yet, so we try again, if it fails
	for i := 0; i < 3; i++ {
		time.Sleep(10 * time.Millisecond)
		var response []string
		response, err = p.Send("AT+CIMI")
		if err != nil {
			continue
		}
		if len(response[0]) != IMSI_LEN || response[1] != "OK" {
			err = fmt.Errorf(response[0])
			continue
		}
		imsi = response[0]
		err = nil
		break
	}
	return imsi, err
}

//PutPubKey stores an ECC public key to the SIM cards secure storage
func (p *Protocol) PutPubKey(name string, uid uuid.UUID, pubKey []byte) error {
	if p.Debug {
		log.Printf(">> put key \"%s\"", name)
	}
	uidBytes, err := uid.MarshalBinary()
	if err != nil {
		return err
	}

	if len(pubKey) != nistp256PubkeyLength {
		return fmt.Errorf("pubkey has invalid length. got: %v, expected: %v", len(pubKey), nistp256PubkeyLength)
	}

	//Verify that the pubkey is valid/on curve (workaround/prevention for the SIM card crashing/hanging if an invalid pubkey is set and later used for verify)
	pubkeyX := new(big.Int)
	pubkeyY := new(big.Int)
	pubkeyX.SetBytes(pubKey[:nistp256XLength])
	pubkeyY.SetBytes(pubKey[nistp256XLength:])
	pubkeyvalid := elliptic.P256().IsOnCurve(pubkeyX, pubkeyY)
	if !pubkeyvalid {
		return fmt.Errorf("pubkey is invalid: coordinates are not on curve")
	}

	//The SIM expects the pubkey in uncompressed SEC format, so it needs to start with 0x04, then X bytes, then Y bytes
	pubKey = append([]byte{0x04}, pubKey...)

	args, err := p.encode([]Tag{
		{0xC4, []byte(name)},             // Entry ID for public key
		{0xC0, uidBytes},                 // Entry title (UUID)
		{0xC1, []byte{0x03}},             // Permission: Read & Write Allowed
		{0xC2, []byte{0x0B, 0x01, 0x00}}, // Key Type: TYPE_EC_FP_PUBLIC, Key Length: LENGTH_EC_FP_256
		{0xC3, pubKey},                   // Public key to be stored (see workaround comment above)
	})
	if err != nil {
		return err
	}
	_, code, err := p.execute(stkAppKeyPut, len(args)/2, args)
	if err != nil {
		return err
	}
	if code != ApduOk {
		return fmt.Errorf("APDU error: %x, storing key failed", code)
	}
	return nil
}

// Get the public key with a given entry ID from the SIM storage.
// Returns a byte array with the raw bytes of the public key.
func (p *Protocol) GetKey(name string) ([]byte, error) {
	if p.Debug {
		log.Printf(">> get key \"%s\"", name)
	}
	// select SS entry
	_, code, err := p.execute(stkAppSsEntrySelect, len(name), hex.EncodeToString([]byte(name)))
	if err != nil {
		return nil, err
	}
	if code == ApduNotFound {
		return nil, fmt.Errorf("entry \"%s\" not found", name)
	}
	_, code, err = p.response(code)
	if err != nil {
		return nil, err
	}
	if code != ApduOk {
		return nil, fmt.Errorf("APDU error: %x, selecting entry failed", code)
	}

	// get public key from selected entry
	args, err := p.encode([]Tag{{0xd0, []byte{0x00}}})
	if err != nil {
		return nil, err
	}

	_, code, err = p.execute(stkAppKeyGet, len(args)/2, args)
	if err != nil {
		return nil, err
	}

	data, code, err := p.response(code)
	if err != nil {
		return nil, err
	}
	if code != ApduOk {
		return nil, fmt.Errorf("APDU error: %x, getting key failed", code)
	}

	tags, err := p.decode(data)
	if err != nil {
		return nil, err
	}

	pubkey, err := p.findTag(tags, 0xc3)
	if err != nil {
		return nil, err
	}

	// return the public key and remove the static 0x04 from the beginning
	// the 0x04 is caused by the SIM returning the key in uncompressed SEC format, so it is 0x04, then X bytes, then Y bytes
	return pubkey[1:], nil
}

// Get the UUID for a given name from the SIM storage.
func (p *Protocol) GetUUID(name string) (uuid.UUID, error) {
	if p.Debug {
		log.Printf(">> get UUID of \"%s\"", name)
	}
	// select SS entry
	_, code, err := p.execute(stkAppSsEntrySelect, len(name), hex.EncodeToString([]byte(name)))
	if err != nil {
		return uuid.Nil, err
	}
	if code == ApduNotFound {
		return uuid.Nil, fmt.Errorf("entry \"%s\" not found", name)
	}
	data, code, err := p.response(code)
	if err != nil {
		return uuid.Nil, err
	}
	if code != ApduOk {
		return uuid.Nil, fmt.Errorf("APDU error: %x, selecting SS entry (%s) failed", code, name)
	}

	// get UUID from entry title
	tags, err := p.decode(data)
	if err != nil {
		return uuid.Nil, err
	}
	entryTitle, err := p.findTag(tags, byte(0xc0))
	if err != nil {
		return uuid.Nil, err
	}
	uid, err := uuid.FromBytes(entryTitle)
	if err != nil {
		return uuid.Nil, err
	}
	return uid, nil
}

// [WIP] Get the public key for a given UUID from the SIM storage.
func (p *Protocol) GetVerificationKey(uid uuid.UUID) ([]byte, error) {
	uidBytes, err := uid.MarshalBinary()
	if err != nil {
		return nil, err
	}
	// get the entry ID that has UUID as entry title
	_, code, err := p.execute(stkAppSsEntryIdGet, len(uidBytes), hex.EncodeToString(uidBytes))
	if err != nil {
		return nil, err
	}
	data, code, err := p.response(code)
	if err != nil {
		return nil, err
	}
	if code != ApduOk {
		return nil, fmt.Errorf("retrieving key entry ID for UUID %s failed. APDU error: %x", uid.String(), code)
	}
	tags, err := p.decode(data)
	if err != nil {
		return nil, err
	}
	keyName, err := p.findTag(tags, byte(0xc4))
	log.Printf("retrieved entry ID: %s", string(keyName))

	// get the key from this entry and return it
	return p.GetKey(string(keyName))
}

// Generate a key pair on the SIM card and store it using the given name and the UUID that is
// later used for the ubirch-protocol. The name for private keys is prefixed with an underscore
// ("_") and the public key gets the name as is. This API automatically selects the right name.
// FIXME overwrites existing keys
func (p *Protocol) GenerateKey(name string, uid uuid.UUID) error {
	if p.Debug {
		log.Printf(">> generate new key \"%s\"", name)
	}
	uidBytes, err := uid.MarshalBinary()
	if err != nil {
		return err
	}

	args, err := p.encode([]Tag{
		{0xC4, []byte(name)},       // Entry ID (public key)
		{0xC0, uidBytes},           // Entry title
		{0xC1, []byte{0x03}},       // Permission: Read & Write Allowed
		{0xC4, []byte("_" + name)}, // Entry ID (private key))
		{0xC0, uidBytes},           // Entry title
		{0xC1, []byte{0x02}},       // Permission: Only Write Allowed
	})
	if err != nil {
		return err
	}

	_, code, err := p.execute(stkAppKeyGenerate, len(args)/2, args)
	if err != nil {
		return err
	}
	if code != ApduOk {
		return fmt.Errorf("APDU error: %x, generate key failed", code)
	}
	return err
}

func (p *Protocol) GenerateCSR(entryID string, uid uuid.UUID) ([]byte, error) {
	if p.Debug {
		log.Printf(">> generate CSR for \"%s\"", entryID)
	}
	certAttributes, err := p.encodeBinary([]Tag{
		{0xD4, []byte("DE")},
		{0xD5, []byte("Berlin")},
		{0xD6, []byte("Berlin")},
		{0xD7, []byte("ubirch GmbH")},
		{0xD8, []byte("Security")},
		{0xD9, []byte(uid.String())},
		{0xDA, []byte("info@ubirch.com")},
	})
	if err != nil {
		return nil, err
	}

	certArgs, err := p.encodeBinary([]Tag{
		{0xD3, []byte{0x00}},             // Version
		{0xE7, certAttributes},           // Subject Information
		{0xC2, []byte{0x0B, 0x01, 0x00}}, // Subject PKI Algorithm Identifier: Key Type: TYPE_EC_FP_PUBLIC, Key Length: LENGTH_EC_FP_256
		{0xD0, []byte{0x21}},             // Signature Algorithm Identifier: ALG_ECDSA_SHA_256
	})
	if err != nil {
		return nil, err
	}

	args, err := p.encode([]Tag{
		{0xC4, []byte(entryID)},       // Public Key ID of the key to be used as the Public Key carried in the CSR
		{0xC4, []byte("_" + entryID)}, // Private Key ID of the key to be used for signing the CSR
		{0xE5, certArgs},              // Certification Request parameters
	})
	if err != nil {
		return nil, err
	}

	_, code, err := p.execute(stkAppCsrGenerateFirst, len(args)/2, args) // Generate CSR
	if err != nil {
		return nil, err
	}
	if code != 0x6100 {
		return nil, fmt.Errorf("unable to generate certificate signing request: 0x%x", code)
	}

	data, code, err := p.execute(stkGetResponse, 0) // get first part of CSR
	if err != nil {
		return nil, err
	}

	for code == ApduMoreData {
		moreData := ""
		moreData, code, _ = p.execute(stkAppCsrGenerateNext, 0) // get next part of CSR
		data += moreData
	}
	if code != ApduOk {
		return nil, fmt.Errorf("unable to retrieve certificate signing request: 0x%x", code)
	}

	return hex.DecodeString(data)
}

// Store a X.509 certificate in the secure storage of the SIM
func (p *Protocol) StoreCertificate(entryID string, uid uuid.UUID, cert []byte) error {
	if p.Debug {
		log.Printf(">> store certificate for \"%s\"", entryID)
	}
	uidBytes, err := uid.MarshalBinary()
	if err != nil {
		return err
	}

	args, err := p.encode([]Tag{
		{0xC4, []byte(entryID)}, // Entry ID
		{0xC0, uidBytes},        // Entry title
		{0xC1, []byte{0x03}},    // Permission: Read & Write Allowed
		{0xC3, cert},            // Certificate
	})
	if err != nil {
		return err
	}

	for finalBit := 0; len(args) > 0; {
		maxChunkSize := 0xFF * 2
		end := maxChunkSize
		if len(args) < maxChunkSize {
			finalBit = 1 << 7
			end = len(args)
		}
		chunk := args[:end]
		_, code, err := p.execute(stkAppCertStore, finalBit, len(chunk)/2, chunk)
		if err != nil {
			return err
		}
		if code != ApduOk {
			return fmt.Errorf("APDU error: %x", code)
		}
		args = args[end:]
	}
	return nil
}

func (p *Protocol) UpdateCertificate(entryID string, newCert []byte) error {
	if p.Debug {
		log.Printf(">> update certificate for \"%s\"", entryID)
	}
	args, err := p.encode([]Tag{
		{0xC3, newCert},
	})
	if err != nil {
		return err
	}

	// select SS entry
	_, code, err := p.execute(stkAppSsEntrySelect, len(entryID), hex.EncodeToString([]byte(entryID)))
	if err != nil {
		return err
	}
	if code == ApduNotFound {
		return fmt.Errorf("entry \"%s\" not found", entryID)
	}
	_, code, err = p.response(code)
	if err != nil {
		return err
	}
	if code != ApduOk {
		log.Printf("selecting SS entry (%s) failed", entryID)
		return fmt.Errorf("APDU error: %x", code)
	}

	// update certificate
	for finalBit := 0; len(args) > 0; {
		maxChunkSize := 0xFF * 2
		end := maxChunkSize
		if len(args) < maxChunkSize {
			finalBit = 1 << 7
			end = len(args)
		}
		chunk := args[:end]
		_, code, err := p.execute(stkAppCertUpdate, finalBit, len(chunk)/2, chunk)
		if err != nil {
			return err
		}
		if code != ApduOk {
			return fmt.Errorf("APDU error: %x", code)
		}
		args = args[end:]
	}
	return nil
}

// Get the X.509 certificate for a given entry ID from the SIM storage.
// Returns a byte array with the raw bytes of the certificate.
func (p *Protocol) GetCertificate(entryID string) ([]byte, error) {
	if p.Debug {
		log.Printf(">> get certificate \"%s\"", entryID)
	}
	// select SS entry
	_, code, err := p.execute(stkAppSsEntrySelect, len(entryID), hex.EncodeToString([]byte(entryID)))
	if err != nil {
		return nil, err
	}
	if code == ApduNotFound {
		return nil, fmt.Errorf("entry \"%s\" not found", entryID)
	}
	_, code, err = p.response(code)
	if err != nil {
		return nil, err
	}
	if code != ApduOk {
		log.Printf("selecting SS entry (%s) failed", entryID)
		return nil, fmt.Errorf("APDU error: %x", code)
	}

	// get the certificate
	data, code, err := p.execute(stkAppCertGet, 0)
	if err != nil {
		return nil, err
	}
	for code == ApduMoreData {
		moreData := ""
		moreData, code, err = p.execute(stkAppCertGet, 1)
		if err != nil {
			return nil, err
		}
		data += moreData
	}
	if code != ApduOk {
		return nil, fmt.Errorf("APDU error: %x", code)
	}

	// extract the certificate from response tags
	tags, err := p.decode(data)
	if err != nil {
		log.Printf("couldn't decode response tags! %s", data)
		return nil, err
	}
	return p.findTag(tags, 0xc3)
}

// Execute a sign operation using the key selected by the given name. Depending on
// the protocol parameter the sign operation creates a signed or chained ubirch-protocol
// packet (UPP). If the protocol parameter is 0 a normal signing operation on the
// pure value data is executed.
// The method returns the signed data in the form of a ubirch-protocol packet (UPP) or
// the raw signature in case protocol is 0.
func (p *Protocol) Sign(name string, value []byte, protocol ProtocolType, hashBeforeSign bool) ([]byte, error) {
	if p.Debug {
		log.Printf(">> sign with key \"_%s\"", name)
	}
	args, err := p.encode([]Tag{
		{0xc4, []byte("_" + name)}, // Entry ID of signing key
		{0xd0, []byte{0x21}},       // Algorithm to be used: ALG_ECDSA_SHA_256
	})
	if err != nil {
		return nil, err
	}

	if p.Debug {
		log.Printf(">> sign init")
	}
	if hashBeforeSign {
		protocol |= 0x40 // set flag for automatic hashing
	}
	_, code, err := p.execute(stkAppSignInit, protocol, len(args)/2, args)
	if err != nil {
		return nil, fmt.Errorf("sign init failed: %v", err)
	}
	if code != ApduOk {
		return nil, fmt.Errorf("sign init failed: APDU error: %x", code)
	}

	data := hex.EncodeToString(value)
	for finalBit := 0; len(data) > 0; {
		end := 128
		if len(data) <= 128 {
			finalBit = 1 << 7
			end = len(data)
		}
		chunk := data[:end]

		if p.Debug {
			log.Printf(">> sign update/final")
		}
		_, code, err = p.execute(stkAppSignFinal, finalBit, len(chunk)/2, chunk)
		if err != nil {
			return nil, fmt.Errorf("sign update/final failed: %v", err)
		}
		if code != ApduOk {
			break
		}
		data = data[end:]
	}

	data, code, err = p.response(code)
	if err != nil {
		return nil, err
	}
	if code != ApduOk {
		return nil, fmt.Errorf("APDU error: %x, retrieving signed data from SIM failed", code)
	}
	return hex.DecodeString(data)
}

// Execute a verify operation on an UPP using the public key with the given name. Depending on
// the protocol parameter the verify operation checks a signed or chained ubirch-protocol
// packet (UPP).
// Returns true or false.
func (p *Protocol) Verify(name string, upp []byte, protocol ProtocolType) (bool, error) {
	if p.Debug {
		log.Printf(">> verify with key \"%s\"", name)
	}
	//check if data is empty
	if len(upp) < 1 {
		return false, fmt.Errorf("verify failed: no data to verify")
	}
	//check if protocol type is of the supported types
	//(direct data/signature verification (=non-UPP data+sig) is not supported by this function)
	if protocol != Signed && protocol != Chained {
		return false, fmt.Errorf("verify failed: unsupported UPP type")
	}
	args, err := p.encode([]Tag{
		{0xc4, []byte(name)},
		{0xd0, []byte{0x21}},
	})
	if err != nil {
		return false, err
	}

	if p.Debug {
		log.Printf(">> verify init")
	}
	_, code, err := p.execute(stkAppVerifyInit, protocol, len(args)/2, args)
	if err != nil {
		return false, fmt.Errorf("verify init failed: %v", err)
	}
	if code != ApduOk {
		return false, fmt.Errorf("verify init failed: APDU error: %x", code)
	}

	data := hex.EncodeToString(upp)
	for finalBit := 0; len(data) > 0; {
		end := 128
		if len(data) <= 128 {
			finalBit = 1 << 7
			end = len(data)
		}
		chunk := data[:end]

		if p.Debug {
			log.Printf(">> verify update/final")
		}
		_, code, err = p.execute(stkAppVerifyFinal, finalBit, len(chunk)/2, chunk)
		if err != nil {
			return false, fmt.Errorf("verify update/final failed: %v", err)
		}
		if code == ApduIncorrectSignature { //no errors occured, but signature is incorrect
			return false, nil
		}
		if code != ApduOk {
			return false, fmt.Errorf("verify update/final failed: APDU error: %x", code)
		}
		data = data[end:]
	}

	return true, nil
}
