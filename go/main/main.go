package main

import (
	"crypto/sha256"
	"encoding/base64"

	//"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-sim/go/ubirch"
	"go.bug.st/serial.v1"
	"log"
	"math/rand"
	"os"
	"strconv"
	"time"
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

	// try to erase all generated keys (fails due to setting on some cards)
	err = sim.DeleteAll()
	if err != nil {
		log.Print(err)
	}

	data, err := sim.Random(5)
	if err != nil {
		log.Print(err)
	}
	log.Printf("random data: %s", hex.EncodeToString(data))

	uuidBytes, _ := hex.DecodeString(conf.Uuid)
	uid, err := uuid.FromBytes(uuidBytes)

	// try to generate a key (fails if exists already)
	name := "Q"
	err = sim.GenerateKey(name, uid)
	if err != nil {
		log.Printf("key may already exist: %v", err)
	}

	//csr, err := sim.GetCSR(name)
	//if err != nil {
	//	log.Fatalf("unable to produce CSR: %v", err)
	//} else {
	//	log.Printf("CSR: " + hex.EncodeToString(csr))
	//}

	// get the public key (see next part, registering)
	key, err := sim.GetKey(name)
	if err != nil {
		log.Fatalf("no key entry found for %s", name)
	} else {
		log.Printf("public key: %s", hex.EncodeToString(key))
	}

	// register public key
	cert, err := getSignedCertificate(&sim, name, uid)
	if err != nil {
		log.Printf("could not generate certificate: %v", err)
	} else {
		log.Printf("certificate: %s", string(cert))
		r, err := post(cert,
			fmt.Sprintf("https://key.%s.ubirch.com/api/keyService/v1/pubkey", conf.Env),
			conf.Api.Key, map[string]string{"Content-Type": "application/json"})
		if err != nil {
			log.Printf("unable to read response body: %v", err)
		} else {
			log.Printf("response: %s", string(r))
		}
	}

	// send a signed message
	type Payload struct {
		Timestamp int
		Value     int
	}
	p := Payload{int(time.Now().Unix()), int(rand.Uint32())}

	pRendered, err := json.Marshal(p)
	if err != nil {
		log.Printf("can't render payload as json: %v", err)
	} else {
		log.Print(string(pRendered))

		// create A hash from the payload to be inserted into the UPP
		digest := sha256.Sum256(pRendered)
		log.Printf("payload hash: base64 %s", base64.StdEncoding.EncodeToString(digest[:]))
		log.Printf("payload hash: hex    %s", hex.EncodeToString(digest[:]))

		// create A signed UPP message and send it to the ubirch backend
		upp, err := sim.Sign(name, digest[:], ubirch.Signed)
		if err != nil {
			log.Printf("signing failed: %v", err)
		} else {
			log.Printf("upp: %s", hex.EncodeToString(upp))
			r, err := post(upp, fmt.Sprintf("https://niomon.%s.ubirch.com/", conf.Env), conf.Api.Upp, nil)
			if err != nil {
				log.Printf("unable to read response body: %v", err)
			} else {
				log.Printf("response: %s", hex.EncodeToString(r))
			}
		}

		// try to verify the upp locally
		ok, err := sim.Verify(name, upp, ubirch.Signed)
		if err != nil {
			log.Printf("verification (local) failed with error: %v", err)
		} else if ok {
			log.Printf("verification: %v", ok)
		}

	}

	for i := 0; i < 3; i++ {
		p := Payload{int(time.Now().Unix()), int(rand.Uint32())}

		pRendered, err := json.Marshal(p)
		if err != nil {
			log.Printf("can't render payload as json: %v", err)
		} else {
			log.Print(string(pRendered))

			// create A hash from the payload to be inserted into the UPP
			digest := sha256.Sum256(pRendered)
			log.Printf("payload hash: base64 %s", base64.StdEncoding.EncodeToString(digest[:]))
			log.Printf("payload hash: hex    %s", hex.EncodeToString(digest[:]))

			// create A signed UPP message and send it to the ubirch backend
			upp, err := sim.Sign(name, digest[:], ubirch.Chained)
			if err != nil {
				log.Printf("signing failed: %v", err)
			} else {
				log.Printf("upp: %s", hex.EncodeToString(upp))
				r, err := post(upp, fmt.Sprintf("https://niomon.%s.ubirch.com/", conf.Env), conf.Api.Upp, nil)
				if err != nil {
					log.Printf("unable to read response body: %v", err)
				} else {
					log.Printf("response: %s", hex.EncodeToString(r))
				}
			}
		}
	}

}
