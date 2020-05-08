package main

import (
	"errors"
	"go.bug.st/serial"
	"log"
	"regexp"
	"strings"
	"time"
)

type SimSerialPort struct {
	serial.Port
	Debug bool
}

func (sp *SimSerialPort) Send(cmd string) ([]string, error) {
	if sp.Debug {
		log.Printf("+++ %s", cmd)
	}
	_, err := sp.Write([]byte(cmd + "\r\n"))
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, 5)
	matcher := make(chan []string, 1)
	finalizer := make(chan bool, 1)
	go func() {
		crnl := regexp.MustCompile("(\\r+\\n)+")
		pattern := regexp.MustCompile("ERROR|OK")
		response := ""
	loop:
		for {
			select {
			case <-finalizer:
				matcher <- crnl.Split(strings.TrimSpace(response), -1)
				break loop
			default:
				n, err := sp.Read(buffer)
				if err != nil {
					log.Printf("read failed: %v", err)
					matcher <- crnl.Split(strings.TrimSpace(response), -1)
					break loop
				}
				if n > 0 {
					response += string(buffer[0:n])
					if pattern.MatchString(response) {
						splitted := crnl.Split(strings.TrimSpace(response), -1)
						matcher <- splitted
						break loop
					}
				}
			}
		}
	}()

	select {
	case response := <-matcher:
		if sp.Debug {
			for _, l := range response {
				log.Printf("--- %s", l)
			}
		}
		return response, nil
	case <-time.After(20 * time.Second):
		finalizer <- true
		select {
		case response := <-matcher:
			return response, errors.New("timeout receiving response")
		}
	}
}

func (sp *SimSerialPort) Init() {
	// check if the modem is online and initialize it
	r, err := sp.Send("AT+CFUN?")
	if err != nil || r[0] != "+CFUN: 4" {
		// setup modem
		for {
			_, err := sp.Send("AT+CFUN=4,1")
			if err == nil {
				break
			}
		}

	loop:
		for {
			r, err := sp.Send("AT+CFUN?")
			if err != nil {
				log.Printf("error initializing modem: %v, %v\n", err, r)
				//os.Exit(1)
				continue
			}
			for _, n := range r {
				if "+CFUN: 4" == n {
					break loop
				}
			}
		}
	}
}
