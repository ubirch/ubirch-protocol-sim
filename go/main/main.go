package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-sim/go/ubirch"
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

	conf := Config{}
	err = conf.Load("config.json")
	if err != nil {
		log.Fatalf("loading configuration failed: %v", err)
	}

	// Initialize the Interface to the SIM
	var sim ubirch.Protocol
	var imsi string

	if conf.Interface == "modem" {
		sim, err = ubirch.InitGPyModem(port, baud, conf.Debug)
		if err != nil {
			log.Fatalf("Failed to initialize the GPy modem")
		}
		// get SIM IMSI
		imsi, err = sim.GetIMSI()
		if err != nil {
			log.Fatalf("getting IMSI failed: %v", err)
		}
	} else if conf.Interface == "screader" {
		sim, err = ubirch.InitSmartCardReader(port, baud, conf.Debug)
		if err != nil {
			log.Fatalf("Failed to initialize the GPy modem")
		}
		imsi = conf.Imsi
	} else {
		log.Fatalf("Error: please select 'modem' or 'screader'")
	}
	defer sim.Close()

	log.Printf("IMSI: %s", imsi)

	// check if PIN is set in config and bootstrap if unset
	PIN := conf.Pin
	if PIN == "" {
		PIN, err = getPIN(imsi, conf)
		if err != nil {
			log.Fatalf("bootstrapping failed: %v", err)
		}
	}
	log.Printf("PIN: %s", PIN)

	// initialize the ubirch protocol sim interface
	err = sim.Init(PIN)
	if err != nil {
		log.Fatalf("initialization failed: %v", err)
	}

	key_name := "ukey"
	cert_name := "ucrt"

	//// generate a key pair
	//// FIXME overwrites existing keys
	//uuidBytes, err := hex.DecodeString(conf.Uuid)
	//if err != nil {
	//	log.Fatalf("failed to decode hex string: %v", err)
	//}
	//uid, err := uuid.FromBytes(uuidBytes)
	//if err != nil {
	//	log.Fatalf("failed to parse UUID: %v", err)
	//}
	//err = sim.GenerateKey(key_name, uid)
	//if err != nil {
	//	log.Printf("generating key \"%s\" failed: %v", key_name, err)
	//}

	// get the public key from SIM card
	key, err := sim.GetKey(key_name)
	if err != nil {
		log.Fatalf("getting key %s failed: %v", key_name, err)
	}
	log.Printf("public key [base64]: %s", base64.StdEncoding.EncodeToString(key))
	log.Printf("public key [hex]:    %s", hex.EncodeToString(key))

	// get the UUID corresponding to the key
	uid, err := sim.GetUUID(key_name)
	if err != nil {
		log.Fatalf("getting UUID from entry \"%s\" failed: %s", key_name, err)
	}
	log.Printf("UUID: %s", uid.String())

	//// generate CSR
	//csr, err := sim.GenerateCSR(key_name, uid)
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
	//err = sim.StoreCertificate(cert_name, uid, certBytes)
	//if err != nil {
	//	log.Fatalf("storing certificate failed. %s", err)
	//} else {
	//	log.Println("certificate stored")
	//}
	//
	//// update certificate
	//err = sim.UpdateCertificate(cert_name, certBytes)
	//if err != nil {
	//	log.Fatalf("can't update certificate on SIM")
	//} else {
	//	log.Println("updated certificate on SIM")
	//}

	// get X.509 certificate from SIM card
	cert, err := sim.GetCertificate(cert_name)
	if err != nil {
		log.Fatalf("retrieving certificate from SIM failed. %s", err)
	}
	log.Printf("retrieved certificate from SIM: %x", cert)

	// register public key at the UBIRCH backend
	// TODO registerKey(cert, conf) // not implemented in backend yet
	//	registerKeyLegacy(&sim, key_name, uid, conf)

	// send a signed message
	type Payload struct {
		Timestamp int
		ID        string
		Value     int
	}

	p := Payload{int(time.Now().Unix()), uid.String(), int(rand.Uint32())}
	pRendered, err := json.Marshal(p)
	if err != nil {
		log.Fatalf("can't render payload as json: %v", err)
	}
	log.Print(string(pRendered))

	// create a hash from the payload
	digest := sha256.Sum256(pRendered)
	log.Printf("data hash [base64]: %s", base64.StdEncoding.EncodeToString(digest[:]))

	// create a signed UPP message
	//upp, err := sim.Sign(name, digest[:], ubirch.Signed, false) // insert hash into the UPP
	upp, err := sim.Sign(key_name, pRendered, ubirch.Signed, true) // use automatic hashing
	if err != nil {
		log.Fatalf("ERROR signing failed: %v", err)
	}
	log.Printf("UPP [hex]: %s", hex.EncodeToString(upp))

	// try to verify the UPP locally
	ok, err := sim.Verify(key_name, upp, ubirch.Signed)
	if err != nil || !ok {
		log.Fatalf("ERROR local verification failed: %v", err)
	}
	log.Printf("verified: %v", ok)

	// send UPP to the UBIRCH backend
	send(upp, uid, conf)

	for i := 0; i < 3; i++ {
		log.Printf(" - - - - - - - - %d. chained UPP: - - - - - - - - ", i+1)
		p := Payload{int(time.Now().Unix()), uid.String(), int(rand.Uint32())}
		pRendered, err := json.Marshal(p)
		if err != nil {
			log.Fatalf("can't render payload as json: %v", err)
		}
		log.Print(string(pRendered))

		// create a hash from the payload
		digest := sha256.Sum256(pRendered)
		log.Printf("data hash [base64]: %s", base64.StdEncoding.EncodeToString(digest[:]))

		// create a signed UPP message
		//upp, err := sim.Sign(name, digest[:], ubirch.Chained, false)
		upp, err := sim.Sign(key_name, pRendered, ubirch.Chained, true) // use automatic hashing
		if err != nil {
			log.Fatalf("ERROR signing failed: %v", err)
		}
		log.Printf("UPP [hex]: %s", hex.EncodeToString(upp))

		// try to verify the UPP locally
		ok, err := sim.Verify(key_name, upp, ubirch.Chained)
		if err != nil || !ok {
			log.Fatalf("ERROR local verification failed: %v", err)
		}
		log.Printf("verified: %v", ok)

		// send UPP to the UBIRCH backend
		send(upp, uid, conf)
	}
}

func getPIN(imsi string, conf Config) (string, error) {
	if conf.Password == "" {
		return "", fmt.Errorf("no auth token for backend set in config")
	}
	// bootstrap SIM identity and retrieve PIN
	return bootstrap(imsi, conf.BootstrapService, conf.Password)
}

// send a self signed JSON formatted key registration message to the UBIRCH backend
func registerKeyLegacy(p *ubirch.Protocol, name string, uid uuid.UUID, conf Config) {
	if conf.Password == "" {
		return
	}
	// todo this will be replaced by the X.509 cert from SIM card
	// generate a self signed certificate for the public key
	cert, err := getSignedCertificate(p, name, uid)
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

// send a X.509 public key certificate to the UBIRCH backend
func registerKey(cert []byte, conf Config) error {
	return fmt.Errorf("not implemented yet")
}

// send UPP to the UBIRCH backend
func send(upp []byte, uid uuid.UUID, conf Config) {
	if conf.Password == "" {
		return
	}

	statusCode, respBody, err := post(upp, conf.Niomon, map[string]string{
		"X-Ubirch-Hardware-Id": uid.String(),
		"X-Ubirch-Auth-Type":   "ubirch",
		"X-Ubirch-Credential":  base64.StdEncoding.EncodeToString([]byte(conf.Password)),
	})
	if err != nil {
		log.Printf("ERROR: sending UPP failed: %v", err)
	} else if statusCode != http.StatusOK {
		log.Printf("ERROR: request to %s failed with status code %d: %s", conf.Niomon, statusCode, hex.EncodeToString(respBody))
	} else {
		log.Printf("UPP successfully sent. response: %s", hex.EncodeToString(respBody))
	}
}
