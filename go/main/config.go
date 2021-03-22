package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	DEV_STAGE        = "dev"
	DEV_UUID         = "9d3c78ff-22f3-4441-a5d1-85c636d486ff"
	DEV_PUBKEY_ECDSA = "LnU8BkvGcZQPy5gWVUL+PHA0DP9dU61H8DBO8hZvTyI7lXIlG1/oruVMT7gS2nlZDK9QG+ugkRt/zTrdLrAYDA=="
	DEV_PUBKEY_EdDSA = "okA7krya3TZbPNEv8SDQIGR/hOppg/mLxMh+D0vozWY="

	DEMO_STAGE        = "demo"
	DEMO_UUID         = "07104235-1892-4020-9042-00003c94b60b"
	DEMO_PUBKEY_ECDSA = "xm+iIomBRjR3QdvLJrGE1OBs3bAf8EI49FfgBriRk36n4RUYX+0smrYK8tZkl6Lhrt9lzjiUGrXGijRoVE+UjA=="
	DEMO_PUBKEY_EdDSA = "Of93YysDTQ66bSGcL/GS6fJJFsmgJnKstJ/QURiq0lE="

	PROD_STAGE        = "prod"
	PROD_UUID         = "10b2e1a4-56b3-4fff-9ada-cc8c20f93016"
	PROD_PUBKEY_ECDSA = "pJdYoJN0N3QTFMBVjZVQie1hhgumQVTy2kX9I7kXjSyoIl40EOa9MX24SBAABBV7xV2IFi1KWMnC1aLOIvOQjQ=="
	PROD_PUBKEY_EdDSA = "74BIrQbAKFrwF3AJOBgwxGzsAl0B2GCF51pPAEHC5pA="

	defaultKeyURL       = "https://key.%s.ubirch.com/api/keyService/v1/pubkey"
	defaultDataURL      = "https://data.%s.ubirch.com/v1"
	defaultNiomonURL    = "https://niomon.%s.ubirch.com/"
	defaultVerifyURL    = "https://verify.%s.ubirch.com/api/upp"
	defaultBootstrapURL = "https://api.console.%s.ubirch.com/ubirch-web-ui/api/v1/devices/bootstrap"
)

// configuration file structure
type Config struct {
	Password         string   `json:"password"`       // password for the ubirch backend	(mandatory)
	Env              string   `json:"env"`            // ubirch environment					(optional)
	ServerIdentity   identity `json:"serverIdentity"` // backend UUID and public keys   	(optional)
	KeyService       string   `json:"keyService"`     // key service URL					(optional)
	Niomon           string   `json:"niomon"`         // authentication service URL			(optional)
	DataService      string   `json:"data"`           // data service URL					(optional)
	VerifyService    string   `json:"verify"`         // verification service URL			(optional)
	BootstrapService string   `json:"boot"`           // bootstrap service URL				(optional)
	Debug            bool     `json:"debug"`          // enable extended debug output		(optional)
	Uuid             string   `json:"uuid"`           // the device uuid 					(set UUID here if you want to generate a new key pair on the SIM card)
	Pin              string   `json:"pin"`            // the SIM pin						(set PIN here if bootstrapping is not possible)
}

type identity struct {
	UUID   string
	PubKey pubkey
}

type pubkey struct {
	ECDSA string
	EdDSA string
}

var defaultServerIdentities = map[string]identity{
	DEV_STAGE:  {UUID: DEV_UUID, PubKey: pubkey{ECDSA: DEV_PUBKEY_ECDSA, EdDSA: DEV_PUBKEY_EdDSA}},
	DEMO_STAGE: {UUID: DEMO_UUID, PubKey: pubkey{ECDSA: DEMO_PUBKEY_ECDSA, EdDSA: DEMO_PUBKEY_EdDSA}},
	PROD_STAGE: {UUID: PROD_UUID, PubKey: pubkey{ECDSA: PROD_PUBKEY_ECDSA, EdDSA: PROD_PUBKEY_EdDSA}},
}

// Load the config file
func (c *Config) Load(fn string) error {
	fileHandle, err := os.Open(fn)
	if err != nil {
		return err
	}
	defer fileHandle.Close()

	err = json.NewDecoder(fileHandle).Decode(c)
	if err != nil {
		return err
	}

	if c.Debug {
		log.SetLevel(log.DebugLevel)
	}

	if c.Password == "" {
		log.Printf("password not set in config. will skip backend communication.")
	}

	if c.Env == "" {
		c.Env = PROD_STAGE
	}

	// assert Env variable value is a valid UBIRCH backend environment
	if !(c.Env == DEV_STAGE || c.Env == DEMO_STAGE || c.Env == PROD_STAGE) {
		return fmt.Errorf("invalid UBIRCH backend environment: \"%s\"", c.Env)
	}

	log.Debugf("UBIRCH backend \"%s\" environment", c.Env)

	if c.KeyService == "" {
		c.KeyService = fmt.Sprintf(defaultKeyURL, c.Env)
	} else {
		c.KeyService = strings.TrimSuffix(c.KeyService, "/mpack")
	}

	// now make sure the Env variable has the actual environment value that is used in the URL
	c.Env = strings.Split(c.KeyService, ".")[1]

	if c.Niomon == "" {
		c.Niomon = fmt.Sprintf(defaultNiomonURL, c.Env)
	}
	if c.DataService == "" {
		c.DataService = fmt.Sprintf(defaultDataURL, c.Env)
	} else {
		c.DataService = strings.TrimSuffix(c.DataService, "/msgPack")
	}
	if c.VerifyService == "" {
		c.VerifyService = fmt.Sprintf(defaultVerifyURL, c.Env)
	}
	if c.BootstrapService == "" {
		c.BootstrapService = fmt.Sprintf(defaultBootstrapURL, c.Env)
	}

	log.Debugf(" - Key Service: %s", c.KeyService)
	log.Debugf(" - Authentication Service: %s", c.Niomon)
	log.Debugf(" - Data Service: %s", c.DataService)
	log.Debugf(" - Verification Service: %s", c.VerifyService)
	log.Debugf(" - Bootstrapping Service: %s", c.BootstrapService)

	if c.ServerIdentity == (identity{}) {
		c.ServerIdentity = defaultServerIdentities[c.Env]
	}

	return nil
}
