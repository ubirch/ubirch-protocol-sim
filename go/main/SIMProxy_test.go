package main

import (
	"bytes"
	"encoding/hex"
	"log"
	"testing"

	"github.com/ubirch/ubirch-protocol-sim/go/ubirch"
	"go.bug.st/serial.v1"
)

const (
	SIMProxySerialPort = "/dev/ttyACM0"
	SIMProxyBaudrate   = 115200
)

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
	data, err := sim.Random(10)
	if err != nil {
		t.Errorf("Failed to receive random data: %v\n", err)
	}
	log.Printf("random data: %s", hex.EncodeToString(data))
}

func TestSIMProxyGetKey(t *testing.T) {
	const SIMProxyName = "Q"
	expectedPubKey, err := hex.DecodeString("0faa26f35c1b50d79fd07ceca939a421b2f5947df0c98e830d6417ffbabd453564a807f6658314f6e1584ff8d17875cb3c032326200d3a25a99dab76c4514a52")
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
