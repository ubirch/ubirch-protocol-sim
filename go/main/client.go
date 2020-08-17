package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

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
		return 0, nil, fmt.Errorf("post request failed: %v", err)
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
