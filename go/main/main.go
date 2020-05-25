package main

import (
	"fmt"
	"github.com/ubirch/ubirch-protocol-sim/go/ubirch"
	"go.bug.st/serial"
	"log"
	"net/http"
	"os"
	"strconv"
)

func main() {
	log.Println("Register SIM public key at the UBIRCH identity service")
	if len(os.Args) < 3 {
		log.Println("usage: main <port> <baudrate>")
		os.Exit(0)
	}

	port := os.Args[1]
	baud, err := strconv.Atoi(os.Args[2])
	if err != nil {
		log.Printf("baud rate must be integer: %s\n", os.Args[2])
		os.Exit(1)
	}

	mode := &serial.Mode{
		BaudRate: baud,
		Parity:   serial.NoParity,
		DataBits: 8,
		StopBits: serial.OneStopBit,
	}
	s, err := serial.Open(port, mode)
	if err != nil {
		log.Printf("serial port open failed: %v\n", err)
		os.Exit(1)
	}
	serialPort := SimSerialPort{s, false}
	serialPort.Init()

	//noinspection GoUnhandledErrorResult
	defer serialPort.Close()

	conf := Config{}
	err = conf.load("config.json")
	if err != nil {
		log.Fatalf("loading configuration failed: %v", err)
	}

	sim := ubirch.Protocol{SimInterface: &serialPort, Debug: conf.Debug}

	// check if PIN is set in config and bootstrap if unset
	PIN := conf.Pin
	if PIN == "" {
		// get SIM IMSI
		imsi, err := sim.GetIMSI()
		if err != nil {
			log.Fatalf("getting IMSI failed: %v", err)
		}
		log.Printf("IMSI: %s", imsi)

		PIN, err = getPIN(imsi, conf)
		if err != nil {
			log.Fatalf("bootstrapping failed: %v", err)
		}
	}

	// initialize the ubirch protocol sim interface
	err = sim.Init(PIN)
	if err != nil {
		log.Fatalf("initialization failed: %v", err)
	}

	key_name := "ukey"

	// get the UUID corresponding to the key
	uid, err := sim.GetUUID(key_name)
	if err != nil {
		log.Fatalf("getting UUID from entry \"%s\" failed: %s", key_name, err)
	}
	log.Printf("UUID: %s", uid.String())

	// generate a self signed certificate for the public key
	cert, err := getSignedCertificate(&sim, key_name, uid)
	if err != nil {
		log.Fatalf("could not generate key certificate: %v", err)
	}
	log.Printf("certificate: %s", string(cert))

	statusCode, respBody, err := post(cert, conf.KeyService, map[string]string{"Content-Type": "application/json"})
	if err != nil {
		log.Fatalf("ERROR: sending key registration failed: %v", err)
	}
	if statusCode != http.StatusOK {
		log.Fatalf("ERROR: request to %s failed with status code %d: %s", conf.KeyService, statusCode, respBody)
	}
	log.Printf("key registration successful. response: %s", string(respBody))
}

func getPIN(imsi string, conf Config) (string, error) {
	if conf.Password == "" {
		return "", fmt.Errorf("can not bootstrap to acquire PIN: no auth token for backend set in config")
	}
	// bootstrap SIM identity and retrieve PIN
	return bootstrap(imsi, conf.BootstrapService, conf.Password)
}
