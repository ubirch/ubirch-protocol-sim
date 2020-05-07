package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
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

	// get the key
	pubKey, err := p.GetKey(name)
	if err != nil {
		return nil, err
	}

	pubKeyBase64 := base64.StdEncoding.EncodeToString(pubKey)

	// put it all together
	now := time.Now().UTC()
	keyRegistration := KeyRegistration{
		"ecdsa-p256v1",
		now.Format(timeFormat),
		uid.String(),
		pubKeyBase64,
		pubKeyBase64,
		now.Add(24 * 365 * time.Hour).Format(timeFormat),
		now.Format(timeFormat),
	}

	// create string representation and sign it
	jsonKeyReg, err := json.Marshal(keyRegistration)
	if err != nil {
		return nil, err
	}

	signature, err := p.Sign(name, jsonKeyReg, 0, false)
	if err != nil {
		return nil, err
	}

	return json.Marshal(SignedKeyRegistration{
		keyRegistration,
		base64.StdEncoding.EncodeToString(signature),
	})
}

// post A http request to the backend service and return response code and body
func post(upp []byte, url string, headers map[string]string) (int, []byte, error) {
	// force HTTP/1.1 as HTTP/2 will break the headers on the server
	client := &http.Client{
		Transport: &http.Transport{
			TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		},
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(upp))
	if err != nil {
		return 0, nil, fmt.Errorf("can't make new post request: %v", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("sending post request failed: %v", err)
	}
	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("reading response body failed: %v", err)
	}
	return resp.StatusCode, body, nil
}

type bootstrapInfo struct {
	Encrypted bool   `json:"encrypted"`
	PIN       string `json:"pin"`
}

//
func bootstrap(imsi string, serviceURL string, pw string) (pin string, err error) {
	headers := map[string]string{
		"X-Ubirch-IMSI":       imsi,
		"X-Ubirch-Auth-Type":  "ubirch",
		"X-Ubirch-Credential": base64.StdEncoding.EncodeToString([]byte(pw)),
	}
	// force HTTP/1.1 as HTTP/2 will break the headers on the server
	client := &http.Client{
		Transport: &http.Transport{
			TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		},
	}

	// create http get request to key service
	req, err := http.NewRequest("GET", serviceURL, nil)
	if err != nil {
		log.Printf("can't make new get request: %v", err)
		return "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("get request failed; %v", err)
		return "", err
	}
	//noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		log.Printf("request to bootstrap service failed. response code: %s,  %s", resp.Status, string(bodyBytes))
		return "", errors.New(resp.Status)
	}

	// get PIN for SIM card authentication from response
	info := bootstrapInfo{}
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&info)
	if err != nil {
		log.Printf("unable to decode bootstrap response: %v", err)
		return "", err
	}

	if info.Encrypted {
		// decrypt PIN here
	}

	return info.PIN, nil
}
