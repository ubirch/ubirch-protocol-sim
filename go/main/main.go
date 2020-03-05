package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/ubirch/ubirch-protocol-sim/go/ubirch"
	"go.bug.st/serial.v1"
	"log"
	"math/rand"
	"net/http"
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
	sim := ubirch.Protocol{SimInterface: &serialPort, Debug: conf.Sim.Debug}

	// get SIM IMSI
	imsi, err := sim.GetIMSI()
	if err != nil {
		log.Fatalf("getting IMSI failed: %v", err)
	}
	log.Println(imsi)

	// bootstrap SIM identity and retrieve PIN
	PIN, err := bootstrap(imsi, conf.BootstrapService, conf.Password)
	if err != nil {
		log.Fatalf("bootstrapping failed: %v", err)
	}

	// initialize the ubirch protocol sim interface
	err = sim.Init(PIN)
	if err != nil {
		log.Fatalf("initialization failed: %v", err)
	}

	//// generate a key pair
	//uuidBytes, _ := hex.DecodeString(conf.Uuid)
	//uid, err := uuid.FromBytes(uuidBytes)
	//err = sim.GenerateKey(name, uid)
	//if err != nil {
	//	log.Printf("key may already exist: %v", err)
	//}
	//// generate CSR
	//csr, err := sim.GenerateCSR(name, uid)
	//if err != nil {
	//	log.Fatalf("unable to produce CSR: %v", err)
	//} else {
	//	log.Printf("CSR: " + hex.EncodeToString(csr))
	//}
	//
	//// read certificate from file
	//cert, err := ioutil.ReadFile("sim_cert.txt")
	//if err != nil {
	//	log.Fatalf("can't read certificate from file")
	//}
	//certBytes, err := hex.DecodeString(string(cert))
	//
	//// store certificate in SIM card
	//err = sim.StoreCertificate(name, uid, certBytes)
	//if err != nil {
	//	log.Fatalf("storing certificate failed. %s", err)
	//} else {
	//	log.Println("certificate stored")
	//}
	//
	//// update certificate
	//err = sim.UpdateCertificate(name, certBytes)
	//if err != nil {
	//	log.Fatalf("can't update certificate on SIM")
	//} else {
	//	log.Println("updated certificate on SIM")
	//}
	//
	// get X.509 certificate from SIM card
	cert_name := "ucrt"
	simCert, err := sim.GetCertificate(cert_name)
	if err != nil {
		log.Fatalf("retrieving certificate from SIM failed. %s", err)
	} else {
		log.Printf("retrieved certificate from SIM: %x", simCert)
	}
	//// register public key using certificate from SIM
	//statusCode, respBody, err := post(simCert, conf.KeyService, map[string]string{"Content-Type": "application/json"})
	//if err != nil {
	//	log.Printf("unable to read response body: %v", err)
	//} else if statusCode != http.StatusOK {
	//	log.Printf("request to %s failed with status code %d: %s", conf.KeyService, statusCode, respBody)
	//} else {
	//	log.Printf("response: %s", string(respBody))
	//}

	// get the public key (see next part, registering)
	key_name := "ukey"
	key, err := sim.GetKey(key_name)
	if err != nil {
		log.Fatalf("no key entry found for %s", key_name)
	} else {
		log.Printf("public key: base64 %s", base64.StdEncoding.EncodeToString(key))
		log.Printf("public key: hex    %s", hex.EncodeToString(key))
	}

	// get the UUID
	uid, err := sim.GetUUID(key_name)
	if err != nil {
		log.Fatalf("getting UUID from certificate failed. %s", err)
	}
	log.Printf("UUID: %s", uid.String())

	// register public key
	cert, err := getSignedCertificate(&sim, key_name, uid)
	if err != nil {
		log.Printf("could not generate certificate: %v", err)
	} else {
		log.Printf("certificate: %s", string(cert))
		statusCode, respBody, err := post(cert, conf.KeyService, map[string]string{"Content-Type": "application/json"})
		if err != nil {
			log.Printf("unable to read response body: %v", err)
		} else if statusCode != http.StatusOK {
			log.Printf("request to %s failed with status code %d: %s", conf.KeyService, statusCode, respBody)
		} else {
			log.Printf("response: %s", string(respBody))
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
		//upp, err := sim.Sign(name, digest[:], ubirch.Signed, false)
		upp, err := sim.Sign(key_name, pRendered, ubirch.Signed, true) // use automatic hashing
		if err != nil {
			log.Printf("signing failed: %v", err)
		} else {
			log.Printf("upp: %s", hex.EncodeToString(upp))

			statusCode, respBody, err := post(upp, conf.Niomon, map[string]string{
				"X-Ubirch-Hardware-Id": uid.String(),
				"X-Ubirch-Auth-Type":   "ubirch",
				"X-Ubirch-Credential":  base64.StdEncoding.EncodeToString([]byte(conf.Password)),
			})
			if err != nil {
				log.Printf("unable to read response body: %v", err)
			} else if statusCode != http.StatusOK {
				log.Printf("request to %s failed with status code %d: %s", conf.Niomon, statusCode, hex.EncodeToString(respBody))
			} else {
				log.Printf("response: %s", hex.EncodeToString(respBody))
			}
		}

		// try to verify the upp locally
		ok, err := sim.Verify(key_name, upp, ubirch.Signed)
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

			// create a chained UPP message and send it to the ubirch backend
			//upp, err := sim.Sign(name, digest[:], ubirch.Chained, false)
			upp, err := sim.Sign(key_name, pRendered, ubirch.Chained, true) // use automatic hashing
			if err != nil {
				log.Printf("signing failed: %v", err)
			} else {
				log.Printf("upp: %s", hex.EncodeToString(upp))

				statusCode, respBody, err := post(upp, conf.Niomon, map[string]string{
					"X-Ubirch-Hardware-Id": uid.String(),
					"X-Ubirch-Auth-Type":   "ubirch",
					"X-Ubirch-Credential":  base64.StdEncoding.EncodeToString([]byte(conf.Password)),
				})
				if err != nil {
					log.Printf("unable to read response body: %v", err)
				} else if statusCode != http.StatusOK {
					log.Printf("request to %s failed with status code %d: %s", conf.Niomon, statusCode, hex.EncodeToString(respBody))
				} else {
					log.Printf("response: %s", hex.EncodeToString(respBody))
				}
			}
		}
	}
}
