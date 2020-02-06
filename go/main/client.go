package main

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/ubirch/ubirch-protocol-sim/go/ubirch"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

//noinspection GoUnusedExportedType
type CertificateInterface interface {
	getSignedCertificate(name string, uid uuid.UUID) (string, error)
}

// [WIP] this is a legacy method that will be replaced by CSR handling.
//
// This function will get the public key from the card and create a json registration package
// to be sent to the ubirch key service. The json structure is signed and sent to ubirch.
func getSignedCertificate(p *ubirch.Protocol, name string, uid uuid.UUID) ([]byte, error) {
	type KeyRegistration struct {
		Algorithm      string `json:"algorithm"`
		Created        string `json:"created"`
		HwDeviceId     string `json:"hwDeviceId"`
		PubKey         string `json:"pubKey"`
		PubKeyId       string `json:"pubKeyId"`
		ValidNotAfter  string `json:"validNotAfter"`
		ValidNotBefore string `json:"validNotBefore"`
	}

	type SignedKeyRegistration struct {
		PubKeyInfo KeyRegistration `json:"pubKeyInfo"`
		Signature  string          `json:"signature"`
	}
	const timeFormat = "2006-01-02T15:04:05.000Z"

	pubKey, err := p.GetKey(name)
	if err != nil {
		return nil, err
	}

	pubKeyBase64 := base64.StdEncoding.EncodeToString(pubKey)
	now := time.Now()
	keyRegistration := KeyRegistration{
		"ecdsa-p256v1",
		now.Format(timeFormat),
		uid.String(),
		pubKeyBase64,
		pubKeyBase64,
		now.Add(time.Duration(24 * 365 * time.Hour)).Format(timeFormat),
		now.Format(timeFormat),
	}
	jsonKeyReg, err := json.Marshal(keyRegistration)
	if err != nil {
		return nil, err
	}
	log.Print(string(jsonKeyReg))

	signatureAsn1, err := p.Sign(name, jsonKeyReg, 0, false)
	if err != nil {
		return nil, err
	}
	signature := asn1.RawValue{}

	_, err = asn1.Unmarshal(signatureAsn1, &signature)
	if err != nil {
		return nil, err
	}
	// The format of our DER string is 0x02 + rlen + r + 0x02 + slen + s
	rLen := signature.Bytes[1] // The entire length of R + offset of 2 for 0x02 and rlen
	r := signature.Bytes[2 : rLen+2]
	// Ignore the next 0x02 and slen bytes and just take the start of S to the end of the byte array
	s := signature.Bytes[rLen+4:]

	return json.Marshal(SignedKeyRegistration{
		keyRegistration,
		base64.StdEncoding.EncodeToString(append(r, s...)),
	})
}

// post A http request to the backend service and
func post(upp []byte, url string, auth string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(upp))
	if err != nil {
		log.Printf("can't make new post request: %v", err)
		return nil, err
	} else {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", auth))
		resp, err := (&http.Client{}).Do(req)
		if err != nil {
			log.Printf("post failed; %v", err)
		}
		//noinspection GoUnhandledErrorResult
		defer resp.Body.Close()
		return ioutil.ReadAll(resp.Body)
	}
}
