package ubirch

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.bug.st/serial"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

const ( //Global SIMProxy test settings
	SIMProxySerialPort    = "/dev/ttyACM0"
	SIMProxyBaudrate      = 115200
	SIMProxyName          = "ukey"
	SIMProxySerialDebug   = false
	SIMProxyProtocolDebug = false
)

// configuration file structure
type testConfig struct {
	Password string `json:"password"` // password for the ubirch backend	(mandatory)
	Debug    bool   `json:"debug"`    // enable extended debug output		(optional)
	Uuid     string `json:"uuid"`     // the device uuid 					(set UUID here if you want to generate a new key pair on the SIM card)
	Pin      string `json:"pin"`      // the SIM pin						(set PIN here if bootstrapping is not possible)
}

//#############################################
// --- helper functions, required for tests ---
//#############################################

// Load the config file
func (c *testConfig) helperLoad(fn string) error {
	contextBytes, err := ioutil.ReadFile(fn)
	if err != nil {
		return err
	}
	err = json.Unmarshal(contextBytes, c)
	if err != nil {
		log.Fatalf("unable to read configuration %v", err)
		return err
	}
	return nil
}

// helperSimInterface is a helper function to initialize th serial connection
// to the SIM card, currently within a GPy.
// It returns a the Protocol and 'nil' error, if successful
func helperSimInterface(debug bool) (Protocol, error) {
	mode := &serial.Mode{
		BaudRate: SIMProxyBaudrate,
		Parity:   serial.NoParity,
		DataBits: 8,
		StopBits: serial.OneStopBit,
	}
	s, err := serial.Open(SIMProxySerialPort, mode)
	if err != nil {
		return Protocol{}, err
	}
	serialPort := SimSerialPort{Port: s, Debug: debug}
	serialPort.Init()

	return Protocol{SimInterface: &serialPort, Debug: debug}, err
}

// Load the configuration for the test environment
func helperLoadConfig() (testConfig, error) {
	conf := testConfig{}
	err := conf.helperLoad("test_config.json")
	return conf, err
}

// helperSelectFalseApplet selects a false Applet
func helperSelectFalseApplet(p *Protocol) error {
	if p.Debug {
		log.Println(">> select wrong SIM applet")
	}
	const stkAppDefWrong = "D2760001180002FF34108389C0028B01"
	_, code, err := p.execute(stkAppSelect, stkAppDefWrong)
	if err != nil {
		return err
	}
	if code != ApduOk {
		return fmt.Errorf("APDU error: %x, select failed", code)
	}
	return nil
}

//##################################################################
// --- Main Test function, will be executed, if calling 'go test'---
//##################################################################

// TestMain is the main test function, which checks the requirements and executes all other tests,
// or exits with error message
func TestMain(m *testing.M) {
	// load the configuration
	conf, err := helperLoadConfig()
	if err != nil {
		log.Fatalf("\r\n" +
			"###\r\n" +
			"ERROR loading the configuration file,\r\n" +
			"Please copy the 'sample_test_config.json' to 'test_config.json'\r\n" +
			"and enter the correct PIN for the SIM card, you want to test.\r\n" +
			"###")
	}
	// check if PIN was entered into the configuration
	if conf.Pin == "" {
		log.Fatalf("ERROR, PIN number is not provided")
	}
	// Establish Interface to SIM and check if PIN is correct
	sim, err := helperSimInterface(conf.Debug)
	if err != nil {
		log.Fatalf("ERROR initializing")
	}
	err = sim.authenticate(conf.Pin)
	if err != nil {
		sim.Close()
		log.Printf("ERROR PIN number is INCORRECT, please provide the correct PIN to continue")
	}
	sim.Close()

	// run all other tests
	code := m.Run()
	os.Exit(code)
}

//################################################################
// --- SIM function tests with serial interface to SIM card ---
//################################################################

// *WARNING* careful with this function, it can block the SIM card,
// if entering the wrong PIN for 3 times in a row.
// according to [1] 2.1.2
// 		test a wrong PIN, should return error
//		test a nil PIN, should return error
// 		test a very long PIN (65 Byte), should return error
//		test the correct PIN, should pass
func TestSim_VerifyPin(t *testing.T) {
	asserter := assert.New(t)
	requirer := require.New(t)

	conf, err := helperLoadConfig()
	requirer.NoErrorf(err, "failed to load configuration")
	sim, err := helperSimInterface(conf.Debug)
	requirer.NoErrorf(err, "failed to initialize the Serial connection to SIM")
	defer sim.Close()
	// this is necessary before the PIN can be Verified TODO is this a bug?
	requirer.NoErrorf(sim.selectApplet(), "failed to select the Applet")

	// test the wrong PIN
	asserter.Errorf(sim.authenticate("1234"), "failed to falsify the PIN")
	// test a nil PIN
	asserter.Errorf(sim.authenticate(""), "failed to falsify the PIN")
	// test a very long PIN (65 Byte)
	asserter.Errorf(sim.authenticate("12345678901234567890123456789012345678901234567890123456789012345"),
		"failed to falsify the PIN")

	// test the correct PIN
	asserter.NoErrorf(sim.authenticate(conf.Pin), "failed to initialize the SIM application")
}

// TestSim_selectApplet tests selecting the Applet
// according to [1] 2.1.1
//		test with the wrong Application Identifier, should return error
//		test with the correct Apllication Identifier, should pass
func TestSim_selectApplet(t *testing.T) {
	asserter := assert.New(t)
	requirer := require.New(t)

	conf, err := helperLoadConfig()
	requirer.NoErrorf(err, "failed to load configuration")
	sim, err := helperSimInterface(conf.Debug)
	requirer.NoErrorf(err, "failed to initialize the Serial connection to SIM")
	defer sim.Close()

	// test the wrong Application
	asserter.Errorf(helperSelectFalseApplet(&sim), " failed to return error")

	// test the select Application APDU
	asserter.NoErrorf(sim.selectApplet(), "failed to select the applet")
}

// TestSim_GenerateSourceRandom tests the random number generator of the SIM card
// according to [1] 2.1.3
//		test Generate random number with 0 Bytes length, should return error
// 		test Generate random number with 255 Bytes length, out of range, error
// 		test Generate Secure Random with 1 Bytes (MIN), should pass
// 		test Generate Secure Random with 32 Bytes, should pass
// 		test Generate Secure Random number with 254 Bytes and compare to the 32 Bytes, should pass
func TestSim_GenerateSecureRandom(t *testing.T) {
	asserter := assert.New(t)
	requirer := require.New(t)

	conf, err := helperLoadConfig()
	requirer.NoErrorf(err, "failed to load configuration")
	sim, err := helperSimInterface(conf.Debug)
	requirer.NoErrorf(err, "failed to initialize the Serial connection to SIM")
	defer sim.Close()

	// select Application APDU
	requirer.NoErrorf(sim.selectApplet(), "failed to select the applet")
	// Verify PIN APDU
	requirer.NoErrorf(sim.authenticate(conf.Pin), "failed to initialize the SIM application")

	// test Generate random number with 0 Bytes length
	_, err = sim.Random(0)
	asserter.Errorf(err, "failed to throw error for 0 Bytes")
	// test Generate random nuber with 255 Bytes lenngth, out of range
	_, err = sim.Random(255)
	asserter.Errorf(err, "failed to throw error for 255 Bytes, max = 254")
	// test Generate Secure Random with 1 Bytes (MIN)
	_, err = sim.Random(1)
	asserter.NoErrorf(err, "failed to generate random number")
	// test Generate Secure Random with 32 Bytes
	randBytes32, err := sim.Random(32)
	asserter.NoErrorf(err, "failed to generate random number")
	// test Generate Secure Random number with 254 Bytes (MAX) and compare to the 32 Bytes
	randBytes254, err := sim.Random(254)
	asserter.NoErrorf(err, "failed to generate random number")
	asserter.NotContainsf(randBytes254, randBytes32, "the big number should not contain the small number")
}

// TestSim_GenerateSourceRandom tests the random number generator of the SIM card,
// this test does not read the keys and check if they are correct, or have changed.
// according to [1] 2.1.7
func TestSim_GenerateKeyPair(t *testing.T) {
	const (
		testName = "testkey"
		testUUID = "12345678-1234-1234-1234-123456789ABC"
	)
	asserter := assert.New(t)
	requirer := require.New(t)

	conf, err := helperLoadConfig()
	requirer.NoErrorf(err, "failed to load configuration")
	sim, err := helperSimInterface(conf.Debug)
	requirer.NoErrorf(err, "failed to initialize the Serial connection to SIM")
	defer sim.Close()

	// select Application APDU
	requirer.NoErrorf(sim.selectApplet(), "failed to select the applet")
	// Verify PIN APDU
	requirer.NoErrorf(sim.authenticate(conf.Pin), "failed to initialize the SIM application")

	// test Generate Key Pair without name/ID
	asserter.Errorf(sim.GenerateKey("", uuid.MustParse(testUUID)), "failed recognize empty name")
	// test Generate Key Pair
	asserter.NoErrorf(sim.GenerateKey(testName, uuid.MustParse(testUUID)), "failed to generate Key Pair")
	// test Generate Key Pair
	asserter.NoErrorf(sim.GenerateKey(testName, uuid.MustParse(testUUID)), "failed to generate Key Pair")
	// test Generate and replace Key Pair
	asserter.NoErrorf(sim.GenerateKey(testName, uuid.Nil), "failed to generate Key Pair") // TODO, do we need to check for nil UUIDs?
}

//################################################################
// --- library function tests only software, wtih mock device ---
//################################################################

// assert functions
func assertTagsEqual(t *testing.T, expected []Tag, actual []Tag) {
	if len(expected) != len(actual) {
		t.Errorf("len(expected) != len(actual): %d != %d", len(expected), len(actual))
		return
	}

	for i, tag := range expected {
		if tag.Tag != actual[i].Tag {
			t.Errorf("expected tag %02x at index %d, but got %02x", tag.Tag, i, actual[i].Tag)
		}
		if !bytes.Equal(tag.Data, actual[i].Data) {
			t.Errorf("expected tag %d data does not match actual: %s != %s", i,
				hex.EncodeToString(tag.Data), hex.EncodeToString(actual[i].Data))
		}
	}
}

type TestData struct {
	args    []Tag
	encoded string
}

const ArgGetCSREncoded = "D30100E700C2030B0100D00121"

var ArgGetCSR = []Tag{
	{0xD3, []byte{0x00}},
	{0xE7, []byte{}},
	{0xC2, []byte{0x0B, 0x01, 0x00}},
	{0xD0, []byte{0x21}},
}

const ArgGenerateKeyEncoded = "C4025F42C01011111111222233332222555555555555C10103C40142C01011111111222233332222555555555555C10103"

var ArgGenerateKey = []Tag{
	{0xC4, []byte("_B")},
	{0xC0, []byte{0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x22, 0x22, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55}},
	{0xC1, []byte{0x03}},
	{0xC4, []byte("B")},
	{0xC0, []byte{0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x22, 0x22, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55}},
	{0xC1, []byte{0x03}},
}

var TestCases = []TestData{
	{ArgGetCSR, ArgGetCSREncoded},
	{ArgGenerateKey, ArgGenerateKeyEncoded},
}

func TestAPDUEncode(t *testing.T) {
	p := Protocol{nil, true}
	for i, c := range TestCases {
		result, _ := p.encode(c.args)
		if result != c.encoded {
			t.Errorf("case %d, unexpected encoding result %v != %v", i, c.encoded, result)
		}
	}
}

func TestAPDUDecode(t *testing.T) {
	p := Protocol{nil, true}
	for i, c := range TestCases {
		result, err := p.decode(c.encoded)
		if err != nil {
			t.Errorf("case %d: decoding failed: %v", i, err)
		}

		assertTagsEqual(t, c.args, result)
	}
}

func TestAPDUDecodeFails(t *testing.T) {
	broken := []string{
		"01xx",                             // decoding will fail
		"11223344556677889900112233445566", // not enough data
		"FF0301020304",                     // 04 is incorrect, no tag length or data
		"D30100E700C2030B0100D001",         // ArgGetCSREncoded but last byte missing
	}

	p := Protocol{nil, true}
	for i, c := range broken {
		r, err := p.decode(c)
		if err == nil {
			t.Errorf("case %d: decoded broken input: '%s', %v", i, c, r)
		} else {
			log.Print(err)
		}
	}
}

type write func(s string) ([]string, error)

type MockSimSerialPort struct {
	write
}

func (sp MockSimSerialPort) Send(cmd string) ([]string, error) {
	return sp.write(cmd)
}

func (sp MockSimSerialPort) Close() error {
	return nil
}

func TestExecuteFailSend(t *testing.T) {
	writeFails := func(s string) ([]string, error) {
		return nil, errors.New("write failed")
	}

	sim := Protocol{MockSimSerialPort{writeFails}, true}
	_, code, err := sim.execute("whatever")

	if err == nil || code == ApduOk {
		t.Error("execute should have failed")
	}
}

func TestExecuteFails(t *testing.T) {
	responses := [][]string{
		{"OK"},                    // insufficient, missing "+CSIM: X,YYYY"
		{"ERROR"},                 // default error
		{"+CSIM: 6,foobar", "OK"}, // not a hex encoded response
		{"+CSIM: 2,9000", "OK"},   // length and data mismatched
	}

	for _, response := range responses {
		log.Printf("checking response '%s'\n", response)
		writeFails := func(s string) ([]string, error) {
			return response, nil
		}

		sim := Protocol{MockSimSerialPort{writeFails}, true}
		_, code, err := sim.execute("whatever")
		log.Printf("received error %v", err)

		if err == nil || code == ApduOk {
			t.Errorf("response '%s' should have failed", response)
		}
	}
}

func TestExecuteSimpleOk(t *testing.T) {
	writeOkay := func(s string) ([]string, error) {
		return []string{"+CSIM: 4,9000", "OK"}, nil
	}

	sim := Protocol{MockSimSerialPort{writeOkay}, true}
	cmd := "010203040506070809"

	_, code, err := sim.execute(cmd)

	if err != nil || code != ApduOk {
		t.Errorf("execute '%s' failed: %v", cmd, err)
	}
}

func TestExecuteSimpleOkWithData(t *testing.T) {
	data := "0102F1F2"
	writeOkay := func(s string) ([]string, error) {
		return []string{fmt.Sprintf("+CSIM: 12,%s9000", data), "OK"}, nil
	}

	sim := Protocol{MockSimSerialPort{writeOkay}, true}
	cmd := "010203040506070809"

	r, code, err := sim.execute(cmd)

	if err != nil || code != ApduOk {
		t.Errorf("execute '%s' failed: %v", cmd, err)
	}
	if data != r {
		t.Errorf("execute failed: expected %s, but got %s", data, r)
	}
}

func TestProtocol_Init_Mock(t *testing.T) {
	sim := Protocol{MockSimSerialPort{func(s string) ([]string, error) {
		return []string{"+CSIM: 4,9000", "OK"}, nil
	}}, true}
	err := sim.Init("1234")
	if err != nil {
		t.Errorf("init failed: %v", err)
	}
}

func TestDecodeExampleCSRRequest(t *testing.T) {
	examples := []string{
		"C40142C4025F42E559D30100E74CD4024445D5064265726C696ED6064265726C696ED70B75626972636820476D6248D8085365637572697479D90A7562697263682E636F6DDA137365637572697479407562697263682E636F6DC2030B0100D00121",
		"C414CE4A19D55815BC1E220B254AAF6F155FFF12AF47C41481EA21DC786DA274A0689628149E85F03AE8ADA0E551D30100E744D4024553D509436174616C6F6E6961D60942617263656C6F6E61D70447444D53D803474449D909546573742055736572DA1274657374757365724067692D64652E636F6DC2030B0100D00121",
	}

	sim := Protocol{nil, true}
	for _, s := range examples {
		log.Print(s)
		tags, err := sim.decode(s)
		if err != nil {
			t.Errorf("decoding failed: %v", err)
		}
		log.Print("====")
		for _, tag := range tags {
			if tag.Tag == 0xe5 {
				tags, err = sim.decodeBinary(tag.Data)
				for _, tag := range tags {
					if tag.Tag == 0xe7 {
						log.Print("====")
						_, _ = sim.decodeBinary(tag.Data)
					}
				}
			}
		}
	}
}
