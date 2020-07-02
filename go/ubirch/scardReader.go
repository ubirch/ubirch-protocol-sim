package ubirch

import (
	"encoding/hex"
	"fmt"
	"github.com/sf1/go-card/smartcard"
	"log"
	"strconv"
)

type SCardReader struct {
	*smartcard.Card
	Debug bool
}

// executes an APDU command and returns the response
func (scr *SCardReader) Execute(format string, v ...interface{}) (string, uint16, error) {
	cmd := fmt.Sprintf(format, v...)
	atcmd := fmt.Sprintf("%s", cmd)
	response, err := scr.SendAPDU(atcmd)
	if err != nil {
		return "", 0, err
	}
	responseLength := len(response)
	responseData := ""
	responseCode := uint16(0)
	if responseLength >= 4 {
		codeIndex := responseLength - 4
		code, err := strconv.ParseUint(response[codeIndex:], 16, 16)
		if err != nil {
			return "", 0, fmt.Errorf("invalid response code '%s': %s", responseData[codeIndex:], err)
		}
		responseData, responseCode = response[0:codeIndex], uint16(code)

		return responseData, responseCode, err
	} else {
		return "", 0, fmt.Errorf("error executing modem command: %s", response)
	}
}

// Init initializes the SmartCard Reader.
// This function is currently not used and might be unnecessary.
func InitSmartCardReader(port string, baudrate int, debug bool) (Protocol, error) {
	ctx, err := smartcard.EstablishContext()
	if err != nil {
		fmt.Println("Error EstablishContext:", err)
		return Protocol{}, err
	}

	reader, err := ctx.WaitForCardPresent()
	if err != nil {
		fmt.Println("Error WaitForCardPresent:", err)
		return Protocol{}, err
	}

	card, err := reader.Connect()
	if err != nil {
		fmt.Println("Error Connect:", err)
		ctx.Release()
		return Protocol{}, err
	}

	fmt.Printf("Card ATR: %s\n", card.ATR())

	scard := SCardReader{card, debug}
	return Protocol{SimInterface: &scard, Debug: debug}, err
}

// Send an APDU command via the SmartCardReader to the SIM card
// and return the response, or the error code
func (scr *SCardReader) SendAPDU(cmd string) (string, error) {
	if scr.Debug {
		log.Printf("+++ %s", cmd)
	}
	command, err := hex.DecodeString(cmd)
	if err != nil {
		fmt.Println("Error converting cmd into hex", err)
		return "", err
	}
	response, err := scr.TransmitAPDU(command)
	if err != nil {
		fmt.Println("Error TransmitAPDU", err)
		return "", err
	}
	if scr.Debug {
		log.Printf("--- %s", hex.EncodeToString(response))
	}
	// see https://cardwerk.com/smart-card-standard-iso7816-4-section-5-basic-organizations ch. 5.4.5
	// the length is not correct and the command has to be retransmitted again with the correct length
	if len(response) == 2 {
		if response[0] == 0x6C {
			command[len(command)-1] = response[1]
			if scr.Debug {
				log.Printf("++++ %s", hex.EncodeToString(command))
			}
			response, err = scr.TransmitAPDU(command)
			if err != nil {
				fmt.Println("Error ReTransmitAPDU", err)
				return "", err
			}
			if scr.Debug {
				log.Printf("---- %s", hex.EncodeToString(response))
			}
		}
	}
	return hex.EncodeToString(response), nil
}

//
func (scr *SCardReader) SendAT(cmd string) ([]string, error) {
	log.Printf("AT command: %s NOT SUPPORTED with this SIM Interface", cmd)
	return nil, fmt.Errorf("AT command NOT SUPPORTED")
}

// Close the connection to the SmartCardReader
func (scr *SCardReader) Close() error {
	return scr.Disconnect()
}
