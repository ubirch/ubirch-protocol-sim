package main

import (
	//"encoding/base64"
	"encoding/hex"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-sim/go/ubirch"
	"go.bug.st/serial.v1"
	"log"
	"os"
	"strconv"
)

func main() {
	log.Println("SIM Interface Example")
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
	serialPort := SimSerialPort{s, true}
	serialPort.Init()

	//noinspection GoUnhandledErrorResult
	defer serialPort.Close()

	conf := Config{}
	err = conf.load("config.json")
	if err != nil {
		log.Fatalf("loading configuration failed: %v", err)
	}
	sim := ubirch.Protocol{SimInterface: &serialPort, Debug: true}

	// initialize the ubirch protocol sim interface
	err = sim.Init(conf.Sim.Pin)
	if err != nil {
		log.Fatalf("initialization failed: %v", err)
	}

	uuidBytes, _ := hex.DecodeString(conf.Uuid)
	uid, err := uuid.FromBytes(uuidBytes)
	log.Printf("UUID: %v", uid)

	name := "Q"

	//csr, err := sim.GenerateCSR(name, uid)
	//if err != nil {
	//	log.Fatalf("unable to produce CSR: %v", err)
	//} else {
	//	log.Printf("CSR: " + hex.EncodeToString(csr))
	//}

	//// read certificate from file
	//cert, err := ioutil.ReadFile("sim_cert.txt")
	//if err != nil {
	//	log.Fatalf("can't read certificate from file")
	//}
	//certBytes, err := hex.DecodeString(string(cert))

	//// store certificate in SIM card
	//err = sim.StoreCertificate(name, uid, certBytes)
	//if err != nil {
	//	log.Fatalf("storing certificate failed. %s", err)
	//} else {
	//	log.Println("certificate stored")
	//}

	// get certificate from SIM card
	simCert, err := sim.GetCertificate(name)
	if err != nil {
		log.Fatalf("retrieving certificate from SIM failed. %s", err)
	} else {
		log.Printf("retrieved certificate from SIM: %x", simCert)
	}

	//// register public key
	//log.Printf("certificate: %s", string(certBytes))
	//statusCode, respBody, err := post(certBytes, conf.KeyService, map[string]string{"Content-Type": "application/json"})
	//if err != nil {
	//	log.Printf("unable to read response body: %v", err)
	//} else if statusCode != http.StatusOK {
	//	log.Printf("request to %s failed with status code %d: %s", conf.KeyService, statusCode, respBody)
	//} else {
	//	log.Printf("response: %s", string(respBody))
	//}
}
