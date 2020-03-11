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
	const SIMProxyName = "Q"
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
