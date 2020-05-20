package ubirch

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ubirchprotocolgo "github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"go.bug.st/serial"
)

const ( //Global SIMProxy test settings
	SIMProxySerialPort    = "/dev/ttyACM0"
	SIMProxyBaudrate      = 115200
	SIMProxyName          = "ukey"
	SIMProxySerialDebug   = false
	SIMProxyProtocolDebug = false
)

////Constants////
//constants to avoid 'magic numbers' in the code
const (
	lenPubkeyECDSA    = 64
	lenPrivkeyECDSA   = 32
	lenSignatureECDSA = 64
)

////Default Values////
// (for consistent defaults in benchmark/test table entries )
const (
	//defaultName: this should not be 'ukey' or any other 'important' key, this name is used to create (and delete!) entries for tests
	defaultName      = "T"
	defaultUUID      = "6eac4d0b-16e6-4508-8c46-22e7451ea5a1"                                                                                             //"f9038b4b-d3bc-47c9-9968-ea275f1b6de8"
	defaultPriv      = "8f827f925f83b9e676aeb87d14842109bee64b02f1398c6dcdd970d5d6880937"                                                                 //"10a0bef246575ea219e15bffbb6704d2a58b0e4aa99f101f12f0b1ce7a143559"
	defaultPub       = "55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771" //"92bbd65d59aecbdf7b497fb4dcbdffa22833613868ddf35b44f5bd672496664a2cc1d228550ae36a1d0210a3b42620b634dc5d22ecde9e12f37d66eeedee3e6a"
	defaultLastSig   = "c03821e1bbabebce351044168c5016187829bcf60988869f4d0bd3e8a905d38fa0bde9269042ad062262dd6829cc8def9e71e10d0a527671ca5707a436b1f209"
	defaultHash      = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	defaultInputData = "cafedeadbeef11223344556677889900aabbccddeeff"
	defaultDataSize  = 200
	defaultSecret    = "2234567890123456"
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

//Do a verification of the UPP signature with the go ecdsa library
func helperVerifyUPPSignature(t *testing.T, uppBytes []byte, pubkeyBytes []byte) (bool, error) {
	//Check that UPP data is OK in general
	if len(pubkeyBytes) != 64 {
		return false, fmt.Errorf("pubkey is not 64 bytes long")
	}
	if len(uppBytes) <= 66 { //check for minimal UPP packet size
		return false, fmt.Errorf("UPP data is too short (%v bytes)", len(uppBytes))
	}

	//Extract signature, data, and hash of data from UPP
	signature := uppBytes[len(uppBytes)-64:]
	dataToHash := uppBytes[:len(uppBytes)-66]
	hash := sha256.Sum256(dataToHash)

	//Set variables so they are in the format the ecdsa lib expects them
	x := &big.Int{}
	x.SetBytes(pubkeyBytes[0:32])
	y := &big.Int{}
	y.SetBytes(pubkeyBytes[32:64])
	pubkey := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	r, s := &big.Int{}, &big.Int{}
	r.SetBytes(signature[:32])
	s.SetBytes(signature[32:])

	//Do the verification and return result
	verifyOK := ecdsa.Verify(&pubkey, hash[:], r, s)
	return verifyOK, nil
}

//Do a verification of the UPP chain ("lastSignature" in "chained" packets must be the signature of previous UPP)
//data is passed in as an array of byte arrays, each representing one UPP in correct order
//startSignature is the signature before the first packet in the array (=lastSignature in first UPP)
//returns no error if chain verification passes
func helperVerifyUPPChain(t *testing.T, uppsArray [][]byte, startSignature []byte) error {
	if len(uppsArray) == 0 {
		return fmt.Errorf("UPP array is empty")
	}
	expectedUPPlastSig := startSignature
	//iterate over all UPPs in array
	for currUppIndex, currUppData := range uppsArray {
		//Check that this UPP's data is OK in general
		//TODO use library defines instead of magic numbers for signature length and position as soon as they are available
		if len(currUppData) < (1 + 16 + 64 + 1 + 0 + 64) { //check for minimal UPP packet size (VERSION|UUID|PREV-SIGNATURE|TYPE|PAYLOAD|SIGNATURE)
			return fmt.Errorf("UPP data is too short (%v bytes) at UPP index %v", len(currUppData), currUppIndex)
		}
		//copy "last signature" field of current UPP and compare to expectation
		//TODO use library defines instead of magic numbers for signature length and position as soon as they are available
		currUppLastSig := currUppData[22 : 22+64]
		if !bytes.Equal(expectedUPPlastSig, currUppLastSig) {
			return fmt.Errorf("Signature chain mismatch between UPPs at index %v and %v", currUppIndex, currUppIndex-1)
		}
		//save signature of this packet as expected "lastSig" for next packet
		expectedUPPlastSig = currUppData[len(currUppData)-64:]
	}
	//If we reach this, everything was checked without errors
	return nil
}

//checkSignedUPP checks a signed type UPP. Parameters are passed as strings.
//The following checks are performed: signature OK, decoding works, payload as expected
//If everything is OK no error is returned, else the error indicates the failing check.
func helperCheckSignedUPP(t *testing.T, uppData []byte, expectedPayload string, pubKey string) error {
	//Decode Pubkey for checking UPPs
	pubkeyBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		return fmt.Errorf("Test configuration string (pubkey) can't be decoded.\nString was: %v", pubKey)
	}

	//Check each signed UPP...
	//...decoding/payload
	decodedSigned, err := ubirchprotocolgo.Decode(uppData)
	if err != nil {
		return fmt.Errorf("UPP could not be decoded")
	}
	signed := decodedSigned.(*ubirchprotocolgo.SignedUPP)
	expectedPayloadBytes, err := hex.DecodeString(expectedPayload)
	if err != nil {
		return fmt.Errorf("Test configuration string (expectedPayload) can't be decoded. \nString was: %v", expectedPayload)
	}
	if !bytes.Equal(expectedPayloadBytes[:], signed.Payload) {
		return fmt.Errorf("Payload does not match expectation.\nExpected:\n%v\nGot:\n%v", hex.EncodeToString(expectedPayloadBytes[:]), hex.EncodeToString(signed.Payload))
	}
	//...Signature
	verifyOK, err := helperVerifyUPPSignature(t, uppData, pubkeyBytes)
	if err != nil {
		return fmt.Errorf("Signature verification could not be performed, error: %v", err)
	}
	if !verifyOK {
		return fmt.Errorf("Signature is not OK")
	}

	//If we reach this, everything was checked without errors
	return nil
}

//checkChainedUPPs checks an array of chained type UPPs. Parameters are passed as strings.
//The following checks are performed: signatures OK, decoding works, payload as expected, chaining OK
//If everything is OK no error is returned, else the error indicates the failing check.
func helperCheckChainedUPPs(t *testing.T, uppsArray [][]byte, expectedPayloads []string, startSignature string, pubKey string) error {
	//Catch general errors
	if len(uppsArray) == 0 {
		return fmt.Errorf("UPP array is empty")
	}
	if len(uppsArray) != len(expectedPayloads) {
		return fmt.Errorf("Number of UPPs and expected payloads not equal")
	}
	//Decode Pubkey for checking UPPs
	pubkeyBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		return fmt.Errorf("Test configuration string (pubkey) can't be decoded.\nString was: %v", pubKey)
	}
	//Decode last signature
	lastSigBytes, err := hex.DecodeString(startSignature)
	if err != nil {
		return fmt.Errorf("Test configuration string (startSig) can't be decoded.\nString was: %v", startSignature)
	}

	//Check each chained UPP...
	for chainedUppIndex, chainedUppData := range uppsArray {
		//...decoding/payload/hash
		decodedChained, err := ubirchprotocolgo.Decode(chainedUppData)
		if err != nil {
			return fmt.Errorf("UPP could not be decoded for UPP at index %v, error: %v", chainedUppIndex, err)
		}
		chained := decodedChained.(*ubirchprotocolgo.ChainedUPP)
		expectedPayload, err := hex.DecodeString(expectedPayloads[chainedUppIndex])
		if err != nil {
			return fmt.Errorf("Test configuration string (expectedPayload) can't be decoded at index %v.\nString was: %v", chainedUppIndex, expectedPayloads[chainedUppIndex])
		}
		if !bytes.Equal(expectedPayload[:], chained.Payload) {
			return fmt.Errorf("Payload does not match expectation for UPP at index %v\nExpected:\n%v\nGot:\n%v", chainedUppIndex, hex.EncodeToString(expectedPayload[:]), hex.EncodeToString(chained.Payload))
		}
		//...Signature
		verifyOK, err := helperVerifyUPPSignature(t, chainedUppData, pubkeyBytes)
		if err != nil {
			return fmt.Errorf("Signature verification could not be performed due to errors for UPP at index %v, error: %v", chainedUppIndex, err)
		}
		if !verifyOK {
			return fmt.Errorf("Signature is not OK for UPP at index %v", chainedUppIndex)
		}
	}
	//... check chain iself
	err = helperVerifyUPPChain(t, uppsArray, lastSigBytes)
	if err != nil {
		return err //return the info from the chain check error
	}
	//If we reach this, everything was checked without errors
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
		log.Fatalf("ERROR initializing: %v", err)
	}
	// this is necessary before the PIN can be Verified TODO is this a bug?
	err = sim.selectApplet()
	if err != nil {
		sim.Close()
		log.Fatalf("ERROR selecting apllet failed with error %v", err)
	}
	err = sim.authenticate(conf.Pin)
	if err != nil {
		sim.Close()
		log.Fatalf("ERROR PIN number is INCORRECT, please provide the correct PIN to continue\nReturned error: %v", err)
	}
	sim.Close()

	// run all other tests
	code := m.Run()
	os.Exit(code)
}

//################################################################
// --- new concept, test the implemented functions for the SIM ---
//################################################################

// TestSim_Init tests the Initialization of the SIM applet with authentication
//	*NOTE*: no failure provocation implemented
func TestSim_Init(t *testing.T) {
	asserter := assert.New(t)
	requirer := require.New(t)

	conf, err := helperLoadConfig()
	requirer.NoErrorf(err, "failed to load configuration")
	sim, err := helperSimInterface(conf.Debug)
	requirer.NoErrorf(err, "failed to initialize the Serial connection to SIM")
	defer sim.Close()
	// test initializing the SIM applet
	asserter.NoErrorf(sim.Init(conf.Pin), "Initializing Applet failed")
}

// TestSim_GetIMSI tests getting the IMSI from the SIM card
// 		test if the IMSI has the correct length (15) and
//		test if, when getting the IMSI a second time, it has the same value
//	*NOTE*: no failure provocation implemented
func TestSim_GetIMSI(t *testing.T) {
	const imsiLength = 15

	asserter := assert.New(t)
	requirer := require.New(t)

	conf, err := helperLoadConfig()
	requirer.NoErrorf(err, "failed to load configuration")
	sim, err := helperSimInterface(conf.Debug)
	requirer.NoErrorf(err, "failed to initialize the Serial connection to SIM")
	defer sim.Close()

	// test getting the IMSI and check the length
	imsi, err := sim.GetIMSI()
	asserter.NoErrorf(err, "failed to get IMSI")
	asserter.Lenf(imsi, imsiLength, "IMSI has not the right length")
	// test getting the IMSI again and chek the length
	imsiProof, err := sim.GetIMSI()
	asserter.NoErrorf(err, "failed to get IMSI")
	asserter.Lenf(imsiProof, imsiLength, "IMSI has not the right length")
	// compare the two IMSI values, they have to be equal
	asserter.Equalf(imsi, imsiProof, "IMSI is not equal, at second reading")
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

// todo, WIP
func TestProtocol_GetCertificate(t *testing.T) {
	const testName = "unknownName"

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

	// test getting Certificate with unknown ID
	cert, err := sim.GetCertificate(testName)
	asserter.Errorf(err, "got Certificate for unknown ID")
	asserter.Nilf(cert, "Certificate for unknown ID is not 'Nil'")
	// test getting Certificate with empty ID
	cert, err = sim.GetCertificate("")
	asserter.Errorf(err, "got Certificate for unknown ID")
	asserter.Nilf(cert, "Certificate for unknown ID is not 'Nil'")

	// test getting Certificate with empty ID
	cert, err = sim.GetCertificate("ucrt") //todo, why are there so many trailing 0x00 ???
	asserter.NoErrorf(err, "got Certificate for unknown ID")
	asserter.NotNilf(cert, "Certificate for unknown ID is not 'Nil'")
	// check if it is a x509 certificate
	certPEM, err := x509.ParseCertificate(bytes.Trim(cert, "\x00")) //todo, why are there so many trailing 0x00 ???
	asserter.NoErrorf(err, "error parsing the Certificate")
	asserter.NotNilf(certPEM, "Certificate should not be Nil")

	// First, create the set of root certificates. For this example we only
	// have one. It's also possible to omit this in order to use the
	// default root set of the current operating system.
	rootPEM, err := ioutil.ReadFile("ubirch-prod.cacert.pem")
	rootDER, err := ioutil.ReadFile("ubirch-prod.cacert.der")
	rootCertPEM, err := x509.ParseCertificate(bytes.Trim(rootDER, "\x00"))
	requirer.NoErrorf(err, "failed to parse root Certificate")
	requirer.NotNilf(rootCertPEM, "root Certificate is Nil")
	asserter.NoErrorf(certPEM.CheckSignatureFrom(rootCertPEM), "Failed to verify Signature from root")

	requirer.NoErrorf(err, "Missing root Certificate")
	roots := x509.NewCertPool()
	requirer.Truef(roots.AppendCertsFromPEM(rootPEM), "could not append Root Certificate")

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := certPEM.Verify(opts); err != nil {
		log.Printf("failed to verify certificate: " + err.Error())
	}
	//todo currently failing because of reasons, I have to discuss with Micha
}

func TestProtocol_DeleteAll(t *testing.T) {

}

func TestProtocol_GenerateCSR(t *testing.T) {

}

func TestProtocol_GetKey(t *testing.T) {

}

func TestProtocol_GetUUID(t *testing.T) {

}

func TestProtocol_GetVerificationKey(t *testing.T) {

}

func TestProtocol_PutKey(t *testing.T) {

}

//TestSim_Sign_RandomInput tests if sim.Sign can correctly create UPPs
// for random input data for the signed and chained protocol type
//This test always uses the SIM to generate the hash of the data
func TestSim_Sign_RandomInput(t *testing.T) {
	const numberOfTests = 2
	const nrOfChainedUpps = 3
	const dataLength = 200 //bytes

	inputData := make([]byte, dataLength)

	asserter := assert.New(t)
	requirer := require.New(t)

	//do general preparation/initialization
	conf, err := helperLoadConfig()
	requirer.NoErrorf(err, "failed to load configuration")
	sim, err := helperSimInterface(conf.Debug)
	requirer.NoErrorf(err, "failed to initialize the Serial connection to SIM")
	defer sim.Close()
	//get the pubkey from the SIM
	//TODO: Make sure we have a key generated?
	simPubkeyBytes, err := sim.GetKey(SIMProxyName)
	requirer.NoError(err, "Could not get pubkey from SIM")
	requirer.NotZero(len(simPubkeyBytes), "Returned pubkey is empty")
	simPubkey := hex.EncodeToString(simPubkeyBytes)

	//workaround for missing sim.getLastSignature(): create UPP and save signature
	upp, err := sim.Sign(SIMProxyName, []byte("somedata"), Chained, true)
	requirer.NoError(err, "Could not create UPP")
	lastChainSig := hex.EncodeToString(upp[len(upp)-lenSignatureECDSA:])

	//test the random input
	for i := 0; i < numberOfTests; i++ {
		t.Logf("Running random sign test %v/%v", i+1, numberOfTests)
		//generate new input
		_, err := rand.Read(inputData)
		requirer.NoError(err, "Could not generate random data")
		//Calculate hash, TODO: Make this dependent on crypto if more than one crypto is implemented
		inputDataHash := sha256.Sum256(inputData)

		//Create 'Signed' type UPP with data
		t.Log("Creating 'signed' UPP")
		createdSignedUpp, err := sim.Sign(SIMProxyName, inputData[:], Signed, true)
		requirer.NoErrorf(err, "Protocol.SignData() failed for Signed type UPP with input data %v", hex.EncodeToString(inputData))

		//Check created Signed UPP
		expectedPayloadString := hex.EncodeToString(inputDataHash[:])
		err = helperCheckSignedUPP(t, createdSignedUpp, expectedPayloadString, simPubkey)
		asserter.NoError(err, "UPP check failed for Signed type UPP with input data %v", hex.EncodeToString(inputData))

		//Create multiple chained UPPs
		t.Log("Creating 'chained' UPPs")
		createdChainedUpps := make([][]byte, nrOfChainedUpps)
		expectedPayloads := make([]string, nrOfChainedUpps)
		for currUppIndex := range createdChainedUpps {
			createdChainedUpps[currUppIndex], err = sim.Sign(SIMProxyName, inputData[:], Chained, true)
			asserter.NoErrorf(err, "SignData() could not create Chained type UPP for index %v", currUppIndex)
			expectedPayloads[currUppIndex] = hex.EncodeToString(inputDataHash[:]) //build expected payload array for checking later
		}

		//Check the created UPPs
		err = helperCheckChainedUPPs(t, createdChainedUpps, expectedPayloads, lastChainSig, simPubkey)
		asserter.NoError(err, "UPP check failed for Chained type UPPs with input data %v", hex.EncodeToString(inputData))

		//save the last Signature of chain for check in next round TODO: get this using a library function when available
		lastChainUpp := createdChainedUpps[nrOfChainedUpps-1]
		lastChainSig = hex.EncodeToString(lastChainUpp[len(lastChainUpp)-lenSignatureECDSA:])
	}
}

func TestProtocol_StoreCertificate(t *testing.T) {

}

func TestProtocol_UpdateCertificate(t *testing.T) {

}

// TestSIM_Verify verifies UPP packages for different configurations.
//		Tests, which shall pass, have the attribute testPasses = true,
//		Tests, which shall return an error, have the attribute testPasses = false
func TestSim_Verify(t *testing.T) {
	var tests = []struct {
		testName         string
		nameForPutPubKey string
		nameForVerify    string
		UUID             string
		pubKey           string
		input            string
		protoType        ProtocolType
		testPasses       bool
	}{
		{
			testName:         "signed UPP correct '1'",
			nameForPutPubKey: defaultName,
			nameForVerify:    defaultName,
			UUID:             defaultUUID,
			pubKey:           "55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771",
			input:            "9522c4106eac4d0b16e645088c4622e7451ea5a100c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc",
			protoType:        Signed,
			testPasses:       true,
		},
		{
			testName:         "signed UPP correct 'Hello world'",
			nameForPutPubKey: defaultName,
			nameForVerify:    defaultName,
			UUID:             defaultUUID,
			pubKey:           "55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771",
			input:            "9522c4106eac4d0b16e645088c4622e7451ea5a100c4207f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069c440e910e03fd852e6e359685bc4ac06103234fa9b94a1e2f94b338405aa520d5a4e03734d85e43abe5e88f57d2f74e2526b30356c47a6e239dc4cc694f5f9c19d1f",
			protoType:        Signed,
			testPasses:       true,
		},
		{
			testName:         "chained UPP correct without last signature",
			nameForPutPubKey: defaultName,
			nameForVerify:    defaultName,
			UUID:             defaultUUID,
			pubKey:           "55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771",
			input:            "9623c4106eac4d0b16e645088c4622e7451ea5a1c4400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c4204bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459ac440395aac8124d4253347779c883c93ad0c614681d794e789aa2b66b2bdfc2092fabd95c67ca04212741462e4263df3f4db12f9c4cf345fde342edcbb4e2483bb4a",
			protoType:        Chained,
			testPasses:       true,
		},
		{
			testName:         "chained UPP correct with last signature",
			nameForPutPubKey: defaultName,
			nameForVerify:    defaultName,
			UUID:             defaultUUID,
			pubKey:           "55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771",
			input:            "9623c4106eac4d0b16e645088c4622e7451ea5a1c440395aac8124d4253347779c883c93ad0c614681d794e789aa2b66b2bdfc2092fabd95c67ca04212741462e4263df3f4db12f9c4cf345fde342edcbb4e2483bb4a00c420dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986c440f781698b897aea6cd6b171542b060c53723c09dd671db0ddea4e6ff7d82055abaa08dcb731aed8ec12edc548f1fb59f4501846ed84c6fff0a64184db0ed31bdc",
			protoType:        Chained,
			testPasses:       true,
		},
		{
			testName:         "chained type UPP for signed verify",
			nameForPutPubKey: defaultName,
			nameForVerify:    defaultName,
			UUID:             defaultUUID,
			pubKey:           "55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771",
			input:            "9623c4106eac4d0b16e645088c4622e7451ea5a1c440395aac8124d4253347779c883c93ad0c614681d794e789aa2b66b2bdfc2092fabd95c67ca04212741462e4263df3f4db12f9c4cf345fde342edcbb4e2483bb4a00c420dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986c440f781698b897aea6cd6b171542b060c53723c09dd671db0ddea4e6ff7d82055abaa08dcb731aed8ec12edc548f1fb59f4501846ed84c6fff0a64184db0ed31bdc",
			protoType:        Signed,
			testPasses:       false,
		},
		{
			testName:         "plain Type not supported",
			nameForPutPubKey: defaultName,
			nameForVerify:    defaultName,
			UUID:             defaultUUID,
			pubKey:           "55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771",
			input:            "9522c4106eac4d0b16e645088c4622e7451ea5a100c4206b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4bc440bc2a01322c679b9648a9391704e992c041053404aafcdab08fc4ce54a57eb16876d741918d01219abf2dc7913f2d9d49439d350f11d05cdb3f85972ac95c45fc",
			protoType:        Plain,
			testPasses:       false,
		},
		{
			testName:         "chained wrong name for protocol",
			nameForPutPubKey: "B",
			nameForVerify:    defaultName,
			UUID:             defaultUUID,
			pubKey:           "55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771",
			input:            "9623c4106eac4d0b16e645088c4622e7451ea5a1c440395aac8124d4253347779c883c93ad0c614681d794e789aa2b66b2bdfc2092fabd95c67ca04212741462e4263df3f4db12f9c4cf345fde342edcbb4e2483bb4a00c420dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986c440f781698b897aea6cd6b171542b060c53723c09dd671db0ddea4e6ff7d82055abaa08dcb731aed8ec12edc548f1fb59f4501846ed84c6fff0a64184db0ed31bdc",
			protoType:        Chained,
			testPasses:       false,
		},
		{
			testName:         "chained wrong name for Verify",
			nameForPutPubKey: defaultName,
			nameForVerify:    "B",
			UUID:             defaultUUID,
			pubKey:           "55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771",
			input:            "9623c4106eac4d0b16e645088c4622e7451ea5a1c440395aac8124d4253347779c883c93ad0c614681d794e789aa2b66b2bdfc2092fabd95c67ca04212741462e4263df3f4db12f9c4cf345fde342edcbb4e2483bb4a00c420dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986c440f781698b897aea6cd6b171542b060c53723c09dd671db0ddea4e6ff7d82055abaa08dcb731aed8ec12edc548f1fb59f4501846ed84c6fff0a64184db0ed31bdc",
			protoType:        Chained,
			testPasses:       false,
		},
		{
			testName:         "chained empty name for Verify",
			nameForPutPubKey: defaultName,
			nameForVerify:    "",
			UUID:             defaultUUID,
			pubKey:           "55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771",
			input:            "9623c4106eac4d0b16e645088c4622e7451ea5a1c440395aac8124d4253347779c883c93ad0c614681d794e789aa2b66b2bdfc2092fabd95c67ca04212741462e4263df3f4db12f9c4cf345fde342edcbb4e2483bb4a00c420dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986c440f781698b897aea6cd6b171542b060c53723c09dd671db0ddea4e6ff7d82055abaa08dcb731aed8ec12edc548f1fb59f4501846ed84c6fff0a64184db0ed31bdc",
			protoType:        Chained,
			testPasses:       false,
		},
		{
			testName:         "chained empty data",
			nameForPutPubKey: defaultName,
			nameForVerify:    defaultName,
			UUID:             defaultUUID,
			pubKey:           "55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771",
			input:            "",
			protoType:        Chained,
			testPasses:       false,
		},
		{
			testName:         "chained wrong data",
			nameForPutPubKey: defaultName,
			nameForVerify:    defaultName,
			UUID:             defaultUUID,
			pubKey:           "55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771",
			input:            "9623c4116eac4d0b16e645088c4622e7451ea5a1c440395aac8124d4253347779c883c93ad0c614681d794e789aa2b66b2bdfc2092fabd95c67ca04212741462e4263df3f4db12f9c4cf345fde342edcbb4e2483bb4a00c420dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986c440f781698b897aea6cd6b171542b060c53723c09dd671db0ddea4e6ff7d82055abaa08dcb731aed8ec12edc548f1fb59f4501846ed84c6fff0a64184db0ed31bdc",
			protoType:        Chained,
			testPasses:       false,
		},
		{
			testName:         "signed wrong signature",
			nameForPutPubKey: defaultName,
			nameForVerify:    defaultName,
			UUID:             defaultUUID,
			pubKey:           "55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771",
			input:            "9522c4106eac4d0b16e645088c4622e7451ea5a100c4207f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069c440e910e03fd852e6e359685bc4ac06103234fa9b94a1e2f94b338405aa520d5a4e03734d85e43abe5e88f57d2f74e2526b30356c47a6e239dc4cc694f5fab19d1f",
			protoType:        Signed,
			testPasses:       false,
		},
		{
			testName:         "signed invalid protocol type",
			nameForPutPubKey: defaultName,
			nameForVerify:    defaultName,
			UUID:             defaultUUID,
			pubKey:           "55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771",
			input:            "9522c4106eac4d0b16e645088c4622e7451ea5a100c4207f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069c440e910e03fd852e6e359685bc4ac06103234fa9b94a1e2f94b338405aa520d5a4e03734d85e43abe5e88f57d2f74e2526b30356c47a6e239dc4cc694f5fab19d1f",
			protoType:        0x67,
			testPasses:       false,
		},
		{
			testName:         "signed data too short (66 Byte)",
			nameForPutPubKey: defaultName,
			nameForVerify:    defaultName,
			UUID:             defaultUUID,
			pubKey:           "55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771",
			input:            "9522c4106eac4d0b16e645088c4622e7451ea5a100c4207f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069c440e910e03fd852e6e359",
			protoType:        Signed,
			testPasses:       false,
		},
		{
			testName:         "signed data too short(65 Byte)",
			nameForPutPubKey: defaultName,
			nameForVerify:    defaultName,
			UUID:             defaultUUID,
			pubKey:           "55f0feac4f2bcf879330eff348422ab3abf5237a24acaf0aef3bb876045c4e532fbd6cd8e265f6cf28b46e7e4512cd06ba84bcd3300efdadf28750f43dafd771",
			input:            "9522c4106eac4d0b16e645088c4622e7451ea5a100c4207f83657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069c440e910e03fd852e6e359",
			protoType:        Signed,
			testPasses:       false,
		},
	}

	//do general preparation/initialization
	conf, err := helperLoadConfig()
	require.NoErrorf(t, err, "failed to load configuration")
	sim, err := helperSimInterface(conf.Debug)
	require.NoErrorf(t, err, "failed to initialize the Serial connection to SIM")
	defer sim.Close()

	//Iterate over all tests
	for _, currTest := range tests {
		t.Run(currTest.testName, func(t *testing.T) {
			requirer := require.New(t)
			asserter := assert.New(t)

			//Parse the test parameters
			currUUID, err := uuid.Parse(currTest.UUID)
			requirer.NoError(err, "could not parse UUID string for test: %v", currTest.UUID)
			currPubkey, err := hex.DecodeString(currTest.pubKey)
			requirer.NoError(err, "could not parse pubkey string for test: %v", currTest.pubKey)

			// Put the pubkey for the test on the SIM (and make sure we clean it up when we're done using 'defer')
			err = sim.PutPubKey(currTest.nameForPutPubKey, currUUID, currPubkey)
			defer sim.DeleteSSEntryID(currTest.nameForPutPubKey)
			requirer.NoError(err, "putting pubkey on SIM failed")

			// convert test input string to bytes
			inputBytes, err := hex.DecodeString(currTest.input)
			requirer.NoErrorf(err, "decoding test input from string failed, string was: %v", currTest.input)

			// verify test input
			verified, err := sim.Verify(currTest.nameForVerify, inputBytes, currTest.protoType)
			if currTest.testPasses == true {
				asserter.NoErrorf(err, "protocol.Verify() returned error: %v", err)
				asserter.Truef(verified, "test input was not verifiable. Input was %s", currTest.input)
			} else {
				asserter.Errorf(err, "protocol.Verify() returned  no error")
				asserter.Falsef(verified, "test input was verifiable. Input was %s", currTest.input)
			}
		})
	}
}

//################################################################
// --- SIM function tests with serial interface to SIM card ---
//################################################################

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
	conf, err := helperLoadConfig()
	require.NoErrorf(t, err, "failed to load configuration")
	p := Protocol{nil, conf.Debug}
	for i, c := range TestCases {
		result, _ := p.encode(c.args)
		if result != c.encoded {
			t.Errorf("case %d, unexpected encoding result %v != %v", i, c.encoded, result)
		}
	}
}

func TestAPDUDecode(t *testing.T) {
	conf, err := helperLoadConfig()
	require.NoErrorf(t, err, "failed to load configuration")
	p := Protocol{nil, conf.Debug}
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
	conf, err := helperLoadConfig()
	require.NoErrorf(t, err, "failed to load configuration")
	p := Protocol{nil, conf.Debug}
	for i, c := range broken {
		r, err := p.decode(c)
		if err == nil {
			t.Errorf("case %d: decoded broken input: '%s', %v", i, c, r)
		} else {
			t.Log(err)
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
	conf, err := helperLoadConfig()
	require.NoErrorf(t, err, "failed to load configuration")
	sim := Protocol{MockSimSerialPort{writeFails}, conf.Debug}
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
		t.Logf("checking response '%s'\n", response)
		writeFails := func(s string) ([]string, error) {
			return response, nil
		}
		conf, err := helperLoadConfig()
		require.NoErrorf(t, err, "failed to load configuration")
		sim := Protocol{MockSimSerialPort{writeFails}, conf.Debug}
		_, code, err := sim.execute("whatever")
		t.Logf("received error %v", err)

		if err == nil || code == ApduOk {
			t.Errorf("response '%s' should have failed", response)
		}
	}
}

func TestExecuteSimpleOk(t *testing.T) {
	writeOkay := func(s string) ([]string, error) {
		return []string{"+CSIM: 4,9000", "OK"}, nil
	}
	conf, err := helperLoadConfig()
	require.NoErrorf(t, err, "failed to load configuration")
	sim := Protocol{MockSimSerialPort{writeOkay}, conf.Debug}
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
	conf, err := helperLoadConfig()
	require.NoErrorf(t, err, "failed to load configuration")
	sim := Protocol{MockSimSerialPort{writeOkay}, conf.Debug}
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
	conf, err := helperLoadConfig()
	require.NoErrorf(t, err, "failed to load configuration")
	sim := Protocol{MockSimSerialPort{func(s string) ([]string, error) {
		return []string{"+CSIM: 4,9000", "OK"}, nil
	}}, conf.Debug}
	err = sim.Init("1234")
	if err != nil {
		t.Errorf("init failed: %v", err)
	}
}

func TestDecodeExampleCSRRequest(t *testing.T) {
	examples := []string{
		"C40142C4025F42E559D30100E74CD4024445D5064265726C696ED6064265726C696ED70B75626972636820476D6248D8085365637572697479D90A7562697263682E636F6DDA137365637572697479407562697263682E636F6DC2030B0100D00121",
		"C414CE4A19D55815BC1E220B254AAF6F155FFF12AF47C41481EA21DC786DA274A0689628149E85F03AE8ADA0E551D30100E744D4024553D509436174616C6F6E6961D60942617263656C6F6E61D70447444D53D803474449D909546573742055736572DA1274657374757365724067692D64652E636F6DC2030B0100D00121",
	}
	conf, err := helperLoadConfig()
	require.NoErrorf(t, err, "failed to load configuration")
	sim := Protocol{nil, conf.Debug}
	for _, s := range examples {
		t.Log(s)
		tags, err := sim.decode(s)
		if err != nil {
			t.Errorf("decoding failed: %v", err)
		}
		t.Log("====")
		for _, tag := range tags {
			if tag.Tag == 0xe5 {
				tags, err = sim.decodeBinary(tag.Data)
				for _, tag := range tags {
					if tag.Tag == 0xe7 {
						t.Log("====")
						_, _ = sim.decodeBinary(tag.Data)
					}
				}
			}
		}
	}
}
