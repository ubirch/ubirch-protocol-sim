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
	env  string // ubirch environment
	Uuid string // the device uuid to use
	Sim  struct {
		Pin   string // SIM pin
		Debug bool   // currently not used
	}
	Api struct { // TODO remove this part -> legacy
		Key string // authentication token
		Upp string // authentication token
	}
	Password      string `json:"password"`   // password for the ubirch backend	(mandatory)
	KeyService    string `json:"keyService"` // key service URL					(optional)
	Niomon        string `json:"niomon"`     // authentication service URL		(optional)
	DataService   string `json:"data"`       // data service URL				(optional)
	VerifyService string `json:"verify"`     // verification service URL		(optional)
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
	log.Printf("configuration found")

	if c.Password == "" {
		if c.Api.Upp == "" { // TODO this is here for now to handle old config as well
			log.Println("WARNING password missing in config")
		} else {
			c.Password = c.Api.Upp
		}
	}

	if c.env == "" {
		c.env = "prod"
	}

	if c.KeyService == "" {
		c.KeyService = fmt.Sprintf("https://key.%s.ubirch.com/api/keyService/v1/pubkey", c.env)
	} else {
		c.KeyService = strings.TrimSuffix(c.KeyService, "/mpack")
	}

	// now make sure the Env variable has the actual environment value that is used in the URL
	c.env = strings.Split(c.KeyService, ".")[1]

	if c.Niomon == "" {
		c.Niomon = fmt.Sprintf("https://niomon.%s.ubirch.com/", c.env)
	}
	if c.DataService == "" {
		c.DataService = fmt.Sprintf("https://data.%s.ubirch.com/v1", c.env)
	} else {
		c.DataService = strings.TrimSuffix(c.DataService, "/msgPack")
	}
	if c.VerifyService == "" {
		c.VerifyService = fmt.Sprintf("https://verify.%s.ubirch.com/api/upp", c.env)
	}

	return nil
}
