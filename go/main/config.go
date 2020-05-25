package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
)

// configuration file structure
type Config struct {
	Password         string `json:"password"`   // password for the ubirch backend	(mandatory)
	Env              string `json:"env"`        // ubirch environment				(optional)
	KeyService       string `json:"keyService"` // key service URL					(optional)
	Niomon           string `json:"niomon"`     // authentication service URL		(optional)
	DataService      string `json:"data"`       // data service URL					(optional)
	VerifyService    string `json:"verify"`     // verification service URL			(optional)
	BootstrapService string `json:"boot"`       // bootstrap service URL			(optional)
	Debug            bool   `json:"debug"`      // enable extended debug output		(optional)
	Uuid             string `json:"uuid"`       // the device uuid 					(set UUID here if you want to generate a new key pair on the SIM card)
	Pin              string `json:"pin"`        // the SIM pin						(set PIN here if bootstrapping is not possible)
}

// load the config file
func (c *Config) load(fn string) error {
	contextBytes, err := ioutil.ReadFile(fn)
	if err != nil {
		return err
	}

	err = json.Unmarshal(contextBytes, c)
	if err != nil {
		log.Fatalf("unable to read configuration %v", err)
		return err
	}

	//if c.Password == "" {
	//	log.Printf("password not set in config. will skip backend communication.")
	//}

	if c.Env == "" {
		c.Env = "prod"
	}

	if c.KeyService == "" {
		c.KeyService = fmt.Sprintf("https://key.%s.ubirch.com/api/keyService/v1/pubkey", c.Env)
	} else {
		c.KeyService = strings.TrimSuffix(c.KeyService, "/mpack")
	}

	// now make sure the Env variable has the actual environment value that is used in the URL
	c.Env = strings.Split(c.KeyService, ".")[1]

	if c.Niomon == "" {
		c.Niomon = fmt.Sprintf("https://niomon.%s.ubirch.com/", c.Env)
	}
	if c.DataService == "" {
		c.DataService = fmt.Sprintf("https://data.%s.ubirch.com/v1", c.Env)
	} else {
		c.DataService = strings.TrimSuffix(c.DataService, "/msgPack")
	}
	if c.VerifyService == "" {
		c.VerifyService = fmt.Sprintf("https://verify.%s.ubirch.com/api/upp", c.Env)
	}
	if c.BootstrapService == "" {
		c.BootstrapService = fmt.Sprintf("https://api.console.%s.ubirch.com/ubirch-web-ui/api/v1/devices/bootstrap", c.Env)
	}

	return nil
}
