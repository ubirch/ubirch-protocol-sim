package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

// configuration file structure
type Config struct {
	Env  string // ubirch environment
	Uuid string // the device uuid to use
	Sim  struct {
		Pin   string // SIM pin
		Debug bool   // currently not used
	}
	Api struct {
		Key string // authentication token
		Upp string // authentication token
	}
}

// load the config file
func (c *Config) load(fn string) error {
	jsonFile, err := os.Open(fn)
	// if we os.Open returns an error then handle it
	if err != nil {
		return err
	}
	// defer the closing of our jsonFile so that we can parse it later on
	//noinspection GoUnhandledErrorResult
	defer jsonFile.Close()
	configData, _ := ioutil.ReadAll(jsonFile)

	return json.Unmarshal(configData, c)
}
