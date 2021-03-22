package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go.bug.st/serial"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/ubirch/ubirch-protocol-sim/go/ubirch"
)

func main() {
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true, TimestampFormat: "2006-01-02 15:04:05.000 -0700"})

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

	// load configuration from file
	conf := Config{}
	err = conf.Load("config.json")
	if err != nil {
		log.Fatalf("loading configuration failed: %v", err)
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
	serialPort := ubirch.SimSerialPort{Port: s, Debug: conf.Debug}
	//noinspection GoUnhandledErrorResult
	defer serialPort.Close()

	serialPort.Init()

	// get SIM IMSI
	imsi, err := serialPort.GetIMSI()
	if err != nil {
		log.Fatalf("getting IMSI failed: %v", err)
	}
	log.Printf("IMSI: %s", imsi)

	// check if PIN is set in config and bootstrap if unset
	PIN := conf.Pin
	if PIN == "" {
		PIN, err = getPIN(imsi, conf)
		if err != nil {
			log.Fatalf("bootstrapping failed: %v", err)
		}
		log.Infof("PIN: %s", PIN)
	}

	sim := ubirch.Protocol{SimInterface: &serialPort, Debug: conf.Debug}
	//noinspection GoUnhandledErrorResult
	defer sim.Deinit()

	// initialize the ubirch protocol sim interface
	err = sim.Init(PIN)
	if err != nil {
		log.Fatalf("initialization failed: %v", err)
	}

	key_name := "ukey"
	cert_name := "ucrt"

	// generate a new ECDSA key pair for the device, if there is none stored on the SIM yet
	entryExists, err := sim.EntryExists(key_name)
	if err != nil {
		log.Fatalf("checking for entry \"%s\" on SIM failed: %v", key_name, err)
	}
	if !entryExists && conf.Uuid != "" {
		uid, err := uuid.Parse(conf.Uuid)
		if err != nil {
			log.Fatalf("failed to parse UUID: %v", err)
		}

		// generate a key pair !!! overwrites existing keys with that entry ID !!!
		err = sim.GenerateKey(key_name, uid)
		if err != nil {
			log.Printf("generating key \"%s\" failed: %v", key_name, err)
		}
	}

	// get the device UUID associated with the key entry ID
	uid, err := sim.GetUUID(key_name)
	if err != nil {
		log.Fatalf("getting UUID from entry \"%s\" failed: %s", key_name, err)
	}
	log.Printf("device UUID: %s", uid.String())

	// get the device public key from SIM card
	key, err := sim.GetKey(key_name)
	if err != nil {
		log.Fatalf("getting key %s failed: %v", key_name, err)
	}
	log.Printf("device public key [base64]: %s", base64.StdEncoding.EncodeToString(key))

	// create a X.509 certificate signing request (CSR)
	csr, err := sim.GenerateCSR(key_name)
	if err != nil {
		log.Fatalf("unable to create CSR: %v", err)
	}
	log.Printf("X.509 CSR: " + hex.EncodeToString(csr))

	// get X.509 certificate from SIM card
	cert, err := sim.GetCertificate(cert_name)
	if err != nil {
		log.Fatalf("retrieving certificate from SIM failed. %s", err)
	}
	log.Printf("X.509 certificate: %x", cert)

	//// delete currently stored backend public key
	//err = sim.DeleteSSEntry(conf.Env)
	//if err != nil {
	//	log.Fatalf("deleting backend public key failed: %v", err)
	//}

	// store backend public key on the SIM for verification, if the entry does not exist yet
	entryExists, err = sim.EntryExists(conf.Env)
	if err != nil {
		log.Fatalf("checking for entry \"%s\" on SIM failed: %v", conf.Env, err)
	}
	if !entryExists {
		uid, err := uuid.Parse(conf.ServerIdentity.UUID)
		if err != nil {
			log.Fatalf("failed to parse UUID: %v", err)
		}

		pubKey, err := base64.StdEncoding.DecodeString(conf.ServerIdentity.PubKey.ECDSA)
		if err != nil {
			log.Fatalf("decoding base64 encoded public key failed: %v", err)
		}

		err = sim.PutPubKey(conf.Env, uid, pubKey)
		if err != nil {
			log.Fatalf("storing backend public key failed: %v", err)
		}
	}

	// get the backend public key from SIM card
	pubKey, err := sim.GetKey(conf.Env)
	if err != nil {
		log.Fatalf("getting key %s failed: %v", conf.Env, err)
	}
	log.Printf("backend public key [base64]: %s", base64.StdEncoding.EncodeToString(pubKey))

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
	log.Printf("hash [base64]: %s", base64.StdEncoding.EncodeToString(digest[:]))

	// create a signed UPP message
	//upp, err := sim.Sign(name, digest[:], ubirch.Signed, false) // insert hash into the UPP
	upp, err := sim.Sign(key_name, pRendered, ubirch.Signed, true) // use automatic hashing
	if err != nil {
		log.Fatalf("ERROR signing failed: %v", err)
	}
	log.Printf("UPP [hex]: %s", hex.EncodeToString(upp))

	// verify the UPP locally
	ok, err := sim.Verify(key_name, upp, ubirch.Signed)
	if err != nil || !ok {
		log.Fatalf("ERROR local verification failed: %v", err)
	}
	log.Printf("UPP locally verified: %v", ok)

	// send UPP to the UBIRCH backend
	resp := send(upp, uid, conf)

	if resp != nil {
		// verify response signature
		ok, err = sim.Verify(conf.Env, resp, ubirch.ProtocolType(resp[1]))
		if err != nil || !ok {
			log.Fatalf("ERROR backend response signature verification failed: %v", err)
		}
		log.Printf("backend response verified: %v", ok)
	}

	// send chained messages
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
		log.Printf("hash [base64]: %s", base64.StdEncoding.EncodeToString(digest[:]))

		// create a signed UPP message
		//upp, err := sim.Sign(name, digest[:], ubirch.Chained, false)
		upp, err := sim.Sign(key_name, pRendered, ubirch.Chained, true) // use automatic hashing
		if err != nil {
			log.Fatalf("ERROR signing failed: %v", err)
		}
		log.Printf("UPP [hex]: %s", hex.EncodeToString(upp))

		// verify the UPP locally
		ok, err := sim.Verify(key_name, upp, ubirch.Chained)
		if err != nil || !ok {
			log.Fatalf("ERROR local verification failed: %v", err)
		}
		log.Printf("UPP locally verified: %v", ok)

		// send UPP to the UBIRCH backend
		resp := send(upp, uid, conf)

		if resp != nil {
			// verify response signature
			ok, err = sim.Verify(conf.Env, resp, ubirch.ProtocolType(resp[1]))
			if err != nil || !ok {
				log.Fatalf("ERROR backend response signature verification failed: %v", err)
			}
			log.Printf("backend response verified: %v", ok)
		}
	}
}

func getPIN(imsi string, conf Config) (string, error) {
	if conf.Password == "" {
		return "", fmt.Errorf("no auth token for backend set in config")
	}
	// bootstrap SIM identity and retrieve PIN
	return bootstrap(imsi, conf.BootstrapService, conf.Password)
}

// send UPP to the UBIRCH backend
func send(upp []byte, uid uuid.UUID, conf Config) []byte {
	if conf.Password == "" {
		log.Warn("backend auth (\"password\") not set in config - request not sent")
		return nil
	}

	statusCode, respBody, err := post(upp, conf.Niomon, map[string]string{
		"X-Ubirch-Hardware-Id": uid.String(),
		"X-Ubirch-Auth-Type":   "ubirch",
		"X-Ubirch-Credential":  base64.StdEncoding.EncodeToString([]byte(conf.Password)),
	})
	if err != nil {
		log.Errorf("sending UPP failed: %v", err)
		return nil
	}

	if statusCode != http.StatusOK {
		log.Errorf("request to %s failed with status code %d: %s", conf.Niomon, statusCode, hex.EncodeToString(respBody))
		return nil
	}

	log.Printf("UPP successfully sent. response: %s", hex.EncodeToString(respBody))
	return respBody
}
