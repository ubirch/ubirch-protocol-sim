package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"math/big"
	"testing"

	"github.com/ubirch/ubirch-protocol-sim/go/ubirch"
	"go.bug.st/serial.v1"
)

const (
	SIMProxySerialPort = "/dev/ttyACM0"
	SIMProxyBaudrate   = 115200
	SIMProxyName       = "Q"
)

//Do a verification of the UPP signature with the go ecdsa library
func verifyUPPSignature(t *testing.T, uppBytes []byte, pubkeyBytes []byte) bool {
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
	return ecdsa.Verify(&pubkey, hash[:], r, s)
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
	serialPort := SimSerialPort{s, false}
	serialPort.Init()

	//noinspection GoUnhandledErrorResult
	//defer serialPort.Close()

	conf := Config{}
	err = conf.load("test_config.json")
	if err != nil {
		t.Fatalf("loading configuration failed: %v", err)
		return nil
	}
	sim := ubirch.Protocol{SimInterface: &serialPort, Debug: false}

	// initialize the ubirch protocol sim interface
	err = sim.Init(conf.Sim.Pin)
	if err != nil {
		t.Fatalf("initialization failed: %v", err)
		return nil
	}
	return &sim
}

func closeSIMProxy(t *testing.T, sim *ubirch.Protocol) {
	castSIM, ok := sim.SimInterface.(*SimSerialPort)
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
		protocol       byte
		hashBeforeSign bool
	}{
		{
			"32Bytes-Signed-SIMHash",
			"adb6b54894e4c880ceb90f779956e401b989dfca3db6f124a2ae01e85c562e8e",
			ubirch.Signed,
			true,
		},
		{ //This fails although it should work
			"64Bytes-Signed-SIMHash",
			"bda39c243912e5c8e811cc489479d2a2ac7b6efef5b57288bf03b74717890c7c9db6b54894e4c880ceb90f779956e401b989dfca3db6f124a2ae01e85c562e8e",
			ubirch.Signed,
			true,
		},
		{
			"543Bytes-Signed-SIMHash",
			"3fff144ed97ccd4a5bade5c8e3a3716b695b6c62f78828ef9f66fd21a0c1e60ee92d51af4192ec3eae8b716f0b7d35921af0fcedfe5cd15b89dbee9a7fd80c76bdb6d00f9f03d0e2351e5d744548fdf68fea8ca2e8f9962f754f934fb876bbddf3f1dc237f6fabcffbf01ce89e61a95f9921be578a741675511a75a3e857252fb2ec35e52334b5ba28fe3d2510a9f45f5c192eadaa49d1f5d2434c4924806be710b90c9161f78a2f0490826ef4f643dea9237ac3579c0e5eb1ec4c5866585aa59dfcf80c1d7bed3991bef277e9b33db8b7833f1fcaa9c5e4722c5505b902e004b6cd5626da8987c05291b8584c564f16ddc05a5140817254355abe716b3e0c3ca28d049720f1d2e12e4ef055e0e1c98981acf23200d76c10eb9a788b9b35b3797a9473806f4b59248cf56c2391e411a52dea86913293df713100dc4b7306c521604b09addde6a8c471c505f4c58ec7a7131dc67141b8fa0df7d128e0095eb6e88efb9f0a0c29d8abdd92e787136d71733a5596a05adaa43c31261e902a6e8f5937f3f043bf5f8a75f8df9c2f860c0b641f855a25be2760351e9397eea3c292d060835b59736c68cea8f40a922f01f067058d495d08cf5117dff853299d1dbdca9ddff03f01f07c63b057f518a0c8ed43cca4dd28695d6e2b118c819f12b368cf3396f950ef59865755d915e73093775cdcea1e7b4e675470c8ed51354e9d4d60c989a144f7112042024365a434528db782f8b5ed7638feaeac0521a68dc442",
			ubirch.Signed,
			true,
		},
		{ //This should fail, but it does not (Input is too long for a hash)
			"37Bytes-Signed-noSIMHash",
			"1234567890adb6b54894e4c880ceb90f779956e401b989dfca3db6f124a2ae01e85c562e8e",
			ubirch.Signed,
			false,
		},
		{ //This should fail, but it does not (Input is too short for a hash)
			"2Bytes-Signed-noSIMHash",
			"2e8e",
			ubirch.Signed,
			false,
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
			if !(verifyUPPSignature(t, uppBytes, pubkey)) {
				t.Errorf("UPP signature verification failed.")
			}
		}) //End of test anonymous function
	} //end loop over all tests
}
