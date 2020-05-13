package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"testing"

	ubirchprotocolgo "github.com/ubirch/ubirch-protocol-go/ubirch/v2"
	"github.com/ubirch/ubirch-protocol-sim/go/ubirch"
	"go.bug.st/serial"
)

const ( //Global SIMProxy test settings
	SIMProxySerialPort    = "/dev/ttyACM0"
	SIMProxyBaudrate      = 115200
	SIMProxyName          = "ukey"
	SIMProxySerialDebug   = false
	SIMProxyProtocolDebug = false
)

//Do a verification of the UPP signature with the go ecdsa library
func verifyUPPSignature(t *testing.T, uppBytes []byte, pubkeyBytes []byte) (bool, error) {
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
func verifyUPPChain(t *testing.T, uppsArray [][]byte, startSignature []byte) error {
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
func checkSignedUPP(t *testing.T, uppData []byte, expectedPayload string, pubKey string) error {
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
	verifyOK, err := verifyUPPSignature(t, uppData, pubkeyBytes)
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
func checkChainedUPPs(t *testing.T, uppsArray [][]byte, expectedPayloads []string, startSignature string, pubKey string) error {
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
		verifyOK, err := verifyUPPSignature(t, chainedUppData, pubkeyBytes)
		if err != nil {
			return fmt.Errorf("Signature verification could not be performed due to errors for UPP at index %v, error: %v", chainedUppIndex, err)
		}
		if !verifyOK {
			return fmt.Errorf("Signature is not OK for UPP at index %v", chainedUppIndex)
		}
	}
	//... check chain iself
	err = verifyUPPChain(t, uppsArray, lastSigBytes)
	if err != nil {
		return err //return the info from the chain check error
	}
	//If we reach this, everything was checked without errors
	return nil
}

func openAndInitSIMProxy(t *testing.T, port string, baud int) *ubirch.Protocol {

	mode := &serial.Mode{
		BaudRate: baud,
		Parity:   serial.NoParity,
		DataBits: 8,
		StopBits: serial.OneStopBit,
	}
	s, err := serial.Open(port, mode)
	if err != nil {
		t.Fatalf("serial port open failed: %v\n", err)
		return nil
	}
	serialPort := ubirch.SimSerialPort{Port: s, Debug: SIMProxySerialDebug}
	serialPort.Init()

	//noinspection GoUnhandledErrorResult
	//defer serialPort.Close()

	conf := Config{}
	err = conf.Load("test_config.json")
	if err != nil {
		t.Fatalf("loading configuration failed: %v", err)
		return nil
	}
	sim := ubirch.Protocol{SimInterface: &serialPort, Debug: SIMProxyProtocolDebug}

	// initialize the ubirch protocol sim interface
	err = sim.Init(conf.Pin)
	if err != nil {
		t.Fatalf("initialization failed: %v", err)
		return nil
	}
	return &sim
}

func closeSIMProxy(t *testing.T, sim *ubirch.Protocol) {
	castSIM, ok := sim.SimInterface.(*ubirch.SimSerialPort)
	if !ok {
		t.Fatal("Could not cast SIM interface to (*SimSerialPort) for closing.")
	}
	err := castSIM.Close()
	if err != nil {
		t.Fatalf("Closing failed with error: %v", err)
	}
}

func TestSIMProxyRandom(t *testing.T) {
	sim := openAndInitSIMProxy(t, SIMProxySerialPort, SIMProxyBaudrate)
	defer closeSIMProxy(t, sim)

	// get random data from SIM
	data, err := sim.Random(5)
	if err != nil {
		t.Errorf("Failed to receive random data: %v\n", err)
	}
	log.Printf("random data: %s", hex.EncodeToString(data))
}

func TestSIMProxyGetKey(t *testing.T) {
	expectedPubKey, err := hex.DecodeString("2f13190ebfe4164beff5e92eb182f54cc18101968d149cd8dd302d073d2629907242840579fd394cedde91ae94d649ba4b8c45950148044806ed74a005cca762")
	if err != nil {
		t.Fatalf("Failed to parse expected public key: %v, string was: %v", err, expectedPubKey)
	}

	sim := openAndInitSIMProxy(t, SIMProxySerialPort, SIMProxyBaudrate)
	defer closeSIMProxy(t, sim)

	// get public key from SIM
	pubkey, err := sim.GetKey(SIMProxyName)
	if err != nil {
		t.Errorf("Failed to receive public key: %v\n", err)
	}
	log.Printf("pubkey: %s", hex.EncodeToString(pubkey))
	if !bytes.Equal(expectedPubKey, pubkey) {
		t.Errorf("Public key does not match:\nwant: %v\n got: %v\n", hex.EncodeToString(expectedPubKey), hex.EncodeToString(pubkey))
	}
}

func TestSIMProxySign(t *testing.T) {
	var tests = []struct {
		testName       string
		inputData      string
		protocol       ubirch.ProtocolType
		hashBeforeSign bool
		shouldFail     bool
	}{
		//***"signed" tests***
		{
			testName:       "32Bytes-Signed-SIMHash",
			inputData:      "adb6b54894e4c880ceb90f779956e401b989dfca3db6f124a2ae01e85c562e8e",
			protocol:       ubirch.Signed,
			hashBeforeSign: true,
			shouldFail:     false,
		},
		{
			testName:       "64Bytes-Signed-SIMHash",
			inputData:      "bda39c243912e5c8e811cc489479d2a2ac7b6efef5b57288bf03b74717890c7c9db6b54894e4c880ceb90f779956e401b989dfca3db6f124a2ae01e85c562e8e",
			protocol:       ubirch.Signed,
			hashBeforeSign: true,
			shouldFail:     false,
		},
		{
			testName:       "128Bytes-Signed-SIMHash",
			inputData:      "75ec57fff9d76bff8e2cda2844eb18ea0ab0234ea38d16078adcb4d26126fbc1c14389ddcefecd7e6f7a4040b5b78841a967b21fa3edda8d34653e0de7e7ce1fb2dff86ea5f62cb4f607d332797070f836a611dec54f7559dba9b4a71cdf41ec951021e370db82fb2df6196778e95e6084fe25f861ba28d24bc6400387adb65f",
			protocol:       ubirch.Signed,
			hashBeforeSign: true,
			shouldFail:     false,
		},
		{
			testName:       "256Bytes-Signed-SIMHash",
			inputData:      "b2bdea5d756fceca74c5d6662fdbb5276c461907fe282da5a8f2c324d036219d6f414daee4fba0c7a9308f0d2d486cf1a28c193c3bfad8415fcfd9ccfa569921af19d1758b4144a5f6c7de78b44d6b3cd4b3bf18602ffb148f98b73cb2eec5725a567f1cf4b3465b2e82177aa9d5f4f07c8c3ed7207c62c604f121f09dd007c5d12d20450ccacad52f044fc3ee5bf9a57bff936a68fe69738ae14f2220d0bdbd2be23142afe03a975a53b06952eb2fed67cf04389872d38441b15950530a86175dd3787a398c62bb255636b52bcf77558338b590468f3f93e519761b8ae6826b932f9866e0e02364668f98297f51d096e71c7c36d5b60a6f2e11ba343f1c87e8",
			protocol:       ubirch.Signed,
			hashBeforeSign: true,
			shouldFail:     false,
		},
		{
			testName:       "512Bytes-Signed-SIMHash",
			inputData:      "9ffe8edd873f3c409152f51f4614a31517106f42bea640cf50cde0d9327893def4ee85b842dde5f913b4b3e4764d98c61446691ba283a51a443659001b15dfcaa8298e0a5ee14f03748b2eabee6f9567710a83d90be413dcd2fa83d45f2ee2cc44be5161356e2d8ebbed11d851d6e9d1558672f5b7397e102f2909f07ed817cc44608c786c4aaf665db94babe4215f5e93b13bd8c56f1d2d51223143400a5d6102da09e20f5ce498d764efe27120a9dbd029ad4342c4151bb477029f70337691808da857996910110181007475a803bb2c892e279309a735d1953654bd1411cff0f9d92edf96baea11638b5c32d62e101f9b6c703bfa4fa9ca413d1037c229c67be1165f0d50e7b7126e17c9ad42d68ea438f65d09e1905b467a5518dcf3dfccebc662e129c6e6af3cfa42c5332b131582620b048e2917c56026649bd3ce3758c8e2fe36ceb7aa8be45d4b137e426dc741864d8a8469f8ae2ee1b8a06ab3ba2e4ad978e812f3927a22e0d20dfefe92887392119fca9c494eb0f2de430b1c4b01956b24ef48f9ca55bff3521402447b545154f02c59507e7031837cb811cc3b3cf3fc93f4ba8e29b0332858d364febba68222fe2f2766e1aa8f0af5c6a5df18ce7964032f1a04dca2af2585ecb4d5c388473757517360e663f4a74d30e54ddd16f9ae60106c9636dbe1f84efffc940058100bc380c03c1c9a029055953c01500a",
			protocol:       ubirch.Signed,
			hashBeforeSign: true,
			shouldFail:     false,
		},
		{
			testName:       "543Bytes-Signed-SIMHash",
			inputData:      "3fff144ed97ccd4a5bade5c8e3a3716b695b6c62f78828ef9f66fd21a0c1e60ee92d51af4192ec3eae8b716f0b7d35921af0fcedfe5cd15b89dbee9a7fd80c76bdb6d00f9f03d0e2351e5d744548fdf68fea8ca2e8f9962f754f934fb876bbddf3f1dc237f6fabcffbf01ce89e61a95f9921be578a741675511a75a3e857252fb2ec35e52334b5ba28fe3d2510a9f45f5c192eadaa49d1f5d2434c4924806be710b90c9161f78a2f0490826ef4f643dea9237ac3579c0e5eb1ec4c5866585aa59dfcf80c1d7bed3991bef277e9b33db8b7833f1fcaa9c5e4722c5505b902e004b6cd5626da8987c05291b8584c564f16ddc05a5140817254355abe716b3e0c3ca28d049720f1d2e12e4ef055e0e1c98981acf23200d76c10eb9a788b9b35b3797a9473806f4b59248cf56c2391e411a52dea86913293df713100dc4b7306c521604b09addde6a8c471c505f4c58ec7a7131dc67141b8fa0df7d128e0095eb6e88efb9f0a0c29d8abdd92e787136d71733a5596a05adaa43c31261e902a6e8f5937f3f043bf5f8a75f8df9c2f860c0b641f855a25be2760351e9397eea3c292d060835b59736c68cea8f40a922f01f067058d495d08cf5117dff853299d1dbdca9ddff03f01f07c63b057f518a0c8ed43cca4dd28695d6e2b118c819f12b368cf3396f950ef59865755d915e73093775cdcea1e7b4e675470c8ed51354e9d4d60c989a144f7112042024365a434528db782f8b5ed7638feaeac0521a68dc442",
			protocol:       ubirch.Signed,
			hashBeforeSign: true,
			shouldFail:     false,
		},
		{ //This should fail (Input is too long for a hash)
			testName:       "37Bytes-Signed-noSIMHash",
			inputData:      "1234567890adb6b54894e4c880ceb90f779956e401b989dfca3db6f124a2ae01e85c562e8e",
			protocol:       ubirch.Signed,
			hashBeforeSign: false,
			shouldFail:     true,
		},
		{ //This should fail (Input is too short for a hash)
			testName:       "2Bytes-Signed-noSIMHash",
			inputData:      "2e8e",
			protocol:       ubirch.Signed,
			hashBeforeSign: false,
			shouldFail:     true,
		},
		//***"chained" tests***
		{
			testName:       "128Bytes-Chained-SIMHash",
			inputData:      "75ec57fff9d76bff8e2cda2844eb18ea0ab0234ea38d16078adcb4d26126fbc1c14389ddcefecd7e6f7a4040b5b78841a967b21fa3edda8d34653e0de7e7ce1fb2dff86ea5f62cb4f607d332797070f836a611dec54f7559dba9b4a71cdf41ec951021e370db82fb2df6196778e95e6084fe25f861ba28d24bc6400387adb65f",
			protocol:       ubirch.Chained,
			hashBeforeSign: true,
			shouldFail:     false,
		},
		{
			testName:       "120Bytes-Chained-SIMHash",
			inputData:      "8e2cda2844eb18ea0ab0234ea38d16078adcb4d26126fbc1c14389ddcefecd7e6f7a4040b5b78841a967b21fa3edda8d34653e0de7e7ce1fb2dff86ea5f62cb4f607d332797070f836a611dec54f7559dba9b4a71cdf41ec951021e370db82fb2df6196778e95e6084fe25f861ba28d24bc6400387adb65f",
			protocol:       ubirch.Chained,
			hashBeforeSign: true,
			shouldFail:     false,
		},
		{
			testName:       "543Bytes-Chained-SIMHash",
			inputData:      "3fff144ed97ccd4a5bade5c8e3a3716b695b6c62f78828ef9f66fd21a0c1e60ee92d51af4192ec3eae8b716f0b7d35921af0fcedfe5cd15b89dbee9a7fd80c76bdb6d00f9f03d0e2351e5d744548fdf68fea8ca2e8f9962f754f934fb876bbddf3f1dc237f6fabcffbf01ce89e61a95f9921be578a741675511a75a3e857252fb2ec35e52334b5ba28fe3d2510a9f45f5c192eadaa49d1f5d2434c4924806be710b90c9161f78a2f0490826ef4f643dea9237ac3579c0e5eb1ec4c5866585aa59dfcf80c1d7bed3991bef277e9b33db8b7833f1fcaa9c5e4722c5505b902e004b6cd5626da8987c05291b8584c564f16ddc05a5140817254355abe716b3e0c3ca28d049720f1d2e12e4ef055e0e1c98981acf23200d76c10eb9a788b9b35b3797a9473806f4b59248cf56c2391e411a52dea86913293df713100dc4b7306c521604b09addde6a8c471c505f4c58ec7a7131dc67141b8fa0df7d128e0095eb6e88efb9f0a0c29d8abdd92e787136d71733a5596a05adaa43c31261e902a6e8f5937f3f043bf5f8a75f8df9c2f860c0b641f855a25be2760351e9397eea3c292d060835b59736c68cea8f40a922f01f067058d495d08cf5117dff853299d1dbdca9ddff03f01f07c63b057f518a0c8ed43cca4dd28695d6e2b118c819f12b368cf3396f950ef59865755d915e73093775cdcea1e7b4e675470c8ed51354e9d4d60c989a144f7112042024365a434528db782f8b5ed7638feaeac0521a68dc442",
			protocol:       ubirch.Chained,
			hashBeforeSign: true,
			shouldFail:     false,
		},
	}

	//Iterate over all tests
	for _, currTest := range tests {
		t.Run(currTest.testName, func(t *testing.T) {
			log.Printf("Starting test: %v", currTest.testName)
			sim := openAndInitSIMProxy(t, SIMProxySerialPort, SIMProxyBaudrate)
			defer closeSIMProxy(t, sim)

			//load test data
			data, err := hex.DecodeString(currTest.inputData)
			if err != nil {
				t.Fatalf("Failed to decode data string: %v,\nstring was: %v\n", err, currTest.inputData)
			}
			log.Printf("Input data: %v", hex.EncodeToString(data))

			//create UPP on SIM
			uppBytes, err := sim.Sign(SIMProxyName, data, currTest.protocol, currTest.hashBeforeSign)

			//If this is a test that should have failed, check if it really did
			if currTest.shouldFail {
				if err == nil {
					t.Errorf("Call to sim.Sign() should have failed but did not.")
				}
				return //if this is a "fail" test we are done at this point in any case
			}

			//if this is a normal test (not "fail") continue with checks
			if err != nil {
				t.Errorf("Failed to sign UPP: %v\n", err)
			}
			log.Printf("Received UPP: %v", hex.EncodeToString(uppBytes))

			//Check if UPP is empty
			if len(uppBytes) == 0 {
				t.Errorf("Returned UPP data is empty.")
			}

			//Get Pubkey from SIM
			pubkey, err := sim.GetKey(SIMProxyName)
			if err != nil {
				t.Errorf("Failed to receive public key: %v\n", err)
			}

			//Check signature
			verifyOK, err := verifyUPPSignature(t, uppBytes, pubkey)
			if err != nil {
				t.Errorf("UPP signature verification could not be performed: %v", err)
			} else if !(verifyOK) {
				t.Errorf("UPP signature is incorrect.")
			}

		}) //End of test anonymous function
	} //end loop over all tests
}
