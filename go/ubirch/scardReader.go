package ubirch

import (
	"encoding/hex"
	"fmt"
	"github.com/sf1/go-card/smartcard"
	"log"
)

type SCardReader struct {
	*smartcard.Card
	Debug bool
}

func (scr *SCardReader) Init() error {
	ctx, err := smartcard.EstablishContext()
	if err != nil {
		fmt.Println("Error EstablishContext:", err)
		return err
	}
	defer ctx.Release()

	reader, err := ctx.WaitForCardPresent()
	if err != nil {
		fmt.Println("Error waiting for card", err)
		return err
	}

	card, err := reader.Connect()
	if err != nil {
		fmt.Println("Error Connecting", err)
		return err
	}
	defer card.Disconnect()

	fmt.Printf("Card ATR: %s\n", card.ATR())

	return nil
}

//
func (scr *SCardReader) Send(cmd string) (string, error) {
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

	return hex.EncodeToString(response), nil
}

//
func (scr *SCardReader) Close() error {
	return scr.Disconnect()
}
