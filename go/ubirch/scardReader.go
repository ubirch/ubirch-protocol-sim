package ubirch

import (
	"encoding/hex"
	"fmt"
	"github.com/ebfe/scard"
	"log"
)

type SCardReader struct {
	*scard.Card
	Debug bool
}

func (scr *SCardReader) Init() error {
	var err error
	context, err := scard.EstablishContext()
	if err != nil {
		fmt.Println("Error EstablishContext:", err)
		return err
	}

	defer context.Release()

	// List available readers
	readers, err := context.ListReaders()
	if err != nil {
		fmt.Println("Error ListReaders:", err)
		return err
	}

	// Use the first reader
	reader := readers[0]
	fmt.Println("Using reader:", reader)

	// Connect to the card
	card, err := context.Connect(reader, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		fmt.Println("Error Connect:", err)
		return err
	}

	// Disconnect (when needed)
	defer card.Disconnect(scard.LeaveCard)

	return nil
}

func (scr *SCardReader) Send(cmd string) (string, error) {
	if scr.Debug {
		log.Printf("+++ %s", cmd)
	}
	hexCmd, err := hex.DecodeString(cmd)
	if err != nil {
		fmt.Println("Error converting cmd into hex", err)
		return "", err
	}
	response, err := scr.Transmit(hexCmd)
	if err != nil {
		fmt.Println("Error transmitting cmd", err)
		return "", err
	}
	if scr.Debug {
		log.Printf("--- %s", hex.EncodeToString(response))
	}
	return hex.EncodeToString(response), nil
}

func (scr *SCardReader) Close() error {
	return scr.Disconnect(scard.LeaveCard)
}
