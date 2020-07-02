package ubirch

import (
	"errors"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.bug.st/serial"
)

type SimSerialPort struct {
	serial.Port
	Debug bool
}

func (sp *SimSerialPort) SendAPDU(cmd string) (string, error) {
	log.Printf("raw APDU command: %s NOT SUPPORTED with this SIM Interface", cmd)
	return "", fmt.Errorf("raw APDU command not supported")
}

func (sp *SimSerialPort) SendAT(cmd string) ([]string, error) {
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

// executes an APDU command and returns the response
func (sp *SimSerialPort) Execute(format string, v ...interface{}) (string, uint16, error) {
	cmd := fmt.Sprintf(format, v...)
	atcmd := fmt.Sprintf("AT+CSIM=%d,\"%s\"", len(cmd), cmd)
	response, err := sp.SendAT(atcmd)
	if err != nil {
		return "", 0, err
	}
	if response[len(response)-1] == "OK" {
		responseLength := 0
		responseData := ""
		responseCode := uint16(0)

		_, err := fmt.Sscanf(response[0], "+CSIM: %d,%s", &responseLength, &responseData)
		if err != nil {
			return "", 0, err
		}
		if responseLength != len(responseData) {
			return "", 0, errors.New("response length does not match data size")
		}

		if responseLength >= 4 {
			codeIndex := responseLength - 4
			code, err := strconv.ParseUint(responseData[codeIndex:], 16, 16)
			if err != nil {
				return "", 0, fmt.Errorf("invalid response code '%s': %s", responseData[codeIndex:], err)
			}
			responseData, responseCode = responseData[0:codeIndex], uint16(code)
		}
		return responseData, responseCode, err
	} else {
		return "", 0, fmt.Errorf("error executing modem command: %s", response[len(response)-1])
	}
}

func InitGPyModem(port string, baudrate int, debug bool) (Protocol, error) {
	mode := &serial.Mode{
		BaudRate: baudrate,
		Parity:   serial.NoParity,
		DataBits: 8,
		StopBits: serial.OneStopBit,
	}
	s, err := serial.Open(port, mode)
	if err != nil {
		return Protocol{}, err
	}
	serialPort := SimSerialPort{Port: s, Debug: debug}

	//workaround: first command often leads to an error, probably due to port not properly flushed when opening
	//we simply send a irrelevant command first to clear the modem buffer/errors
	_, err = serialPort.SendAT("AT+CFUN?")
	if err != nil {
		log.Printf("could not send modem command: %v\n", err)
	}

	// check if the modem is online and initialize it
	r, err := serialPort.SendAT("AT+CFUN?")
	if err != nil || r[0] != "+CFUN: 4" {
		// setup modem
		for {
			_, err := serialPort.SendAT("AT+CFUN=4,1")
			if err == nil {
				break
			}
		}

	loop:
		for {
			r, err := serialPort.SendAT("AT+CFUN?")
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
	return Protocol{SimInterface: &serialPort, Debug: debug}, err
}

// Close the serial port
func (sp *SimSerialPort) Close() error {
	err := sp.Port.Close()
	return err
}
