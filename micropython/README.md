# Micropython Example (w/ SIM)

Works on a Pycom GPy module (requires at least firmware version 1.19+).

The code needs a file `config.json` (not committed) that looks like this:

> Use a different UUID and ask ubirch for API tokens.

The wifi settings are optional, if you are just using the SIM card as a trusted execution environment.
```json
{
    "wifi": {"ssid": "MyNetwork", "pass": "MyPassword"},
    "apn": "iot.telekom.net",
    "env": "demo",
    "uuid": "848DB5DD65644F7DAFAE46325DB8DFFF",
    "sim": {"pin": "1234", "debug": false},
    "api": {
        "key": "API-Token for key server",
        "upp": "API Token for UPP backend server",
    }
}
```

# LED Status
| LED colour    | Status            |
| ------------- | ------------      |
| blue flashing | initialization    |
| green         | running main loop |
| red           | something went wrong while sending UPP |
| purple        | lost connection and trying to reconnect |
| off           | waiting for next interval |

# Testing

1. Test UPP has arrived correctly and was verifyable:
```bash
curl -d '3W2pCWFB+v3tkJ5p2+QlQDWS5Dsj3QzaphA4ZeX/3Ss=' https://verify.dev.ubirch.com/api/upp
{"upp":"liPEEESNtd1lZE99r65GMl243//EQGhY892X0oEeGMvEmUhHwShBe3kbEHgA1E/+38+nLhhtt8DqfXVzQcpPkkUXWRn293RcwDoTuAlLEoonExMmnYcAxCDdbakJYUH6/e2Qnmnb5CVANZLkOyPdDNqmEDhl5f/dK8RAr56JvcayQvTMPX2sM4p4If2uzC7HL0VGTVE0jHl/3Q2qkscyFfvYfdHbUn2RFY+aheCqlXVlSQ98H0KCgJmqkQ==","prev":null,"anchors":null}
```
2. Test UPP with a extended verification (also includes chain):
```bash
curl -d '3W2pCWFB+v3tkJ5p2+QlQDWS5Dsj3QzaphA4ZeX/3Ss=' https://verify.dev.ubirch.com/api/upp/verify
{"upp":"liPEEESNtd1lZE99r65GMl243//EQGhY892X0oEeGMvEmUhHwShBe3kbEHgA1E/+38+nLhhtt8DqfXVzQcpPkkUXWRn293RcwDoTuAlLEoonExMmnYcAxCDdbakJYUH6/e2Qnmnb5CVANZLkOyPdDNqmEDhl5f/dK8RAr56JvcayQvTMPX2sM4p4If2uzC7HL0VGTVE0jHl/3Q2qkscyFfvYfdHbUn2RFY+aheCqlXVlSQ98H0KCgJmqkQ==","prev":"liPEEESNtd1lZE99r65GMl243//EQNCpfVGMZLzmX4lu9rVxwIUTzqKEiCU257SUtpZa0dRGtuuFyn1xuXmpSawbKxoEXbVQOCgGDFk1Tp3ShMF2gFUAxCBRW/4r/YTyLHa/VuaGWyKQ8LMA8B3NrTnWv5r8qS7Y5cRAaFjz3ZfSgR4Yy8SZSEfBKEF7eRsQeADUT/7fz6cuGG23wOp9dXNByk+SRRdZGfb3dFzAOhO4CUsSiicTEyadhw==","anchors":null}
```
3. Test UPP and include blockchain info when this was data was received (may take up to 1-2 minutes):
```bash
curl -d '3W2pCWFB+v3tkJ5p2+QlQDWS5Dsj3QzaphA4ZeX/3Ss=' https://verify.dev.ubirch.com/api/upp/verify/anchors
{"upp":"liPEEESNtd1lZE99r65GMl243//EQGhY892X0oEeGMvEmUhHwShBe3kbEHgA1E/+38+nLhhtt8DqfXVzQcpPkkUXWRn293RcwDoTuAlLEoonExMmnYcAxCDdbakJYUH6/e2Qnmnb5CVANZLkOyPdDNqmEDhl5f/dK8RAr56JvcayQvTMPX2sM4p4If2uzC7HL0VGTVE0jHl/3Q2qkscyFfvYfdHbUn2RFY+aheCqlXVlSQ98H0KCgJmqkQ==","prev":"liPEEESNtd1lZE99r65GMl243//EQNCpfVGMZLzmX4lu9rVxwIUTzqKEiCU257SUtpZa0dRGtuuFyn1xuXmpSawbKxoEXbVQOCgGDFk1Tp3ShMF2gFUAxCBRW/4r/YTyLHa/VuaGWyKQ8LMA8B3NrTnWv5r8qS7Y5cRAaFjz3ZfSgR4Yy8SZSEfBKEF7eRsQeADUT/7fz6cuGG23wOp9dXNByk+SRRdZGfb3dFzAOhO4CUsSiicTEyadhw==","anchors":[{"label":"PUBLIC_CHAIN","properties":{"timestamp":"2019-12-11T10:22:55.994Z","hash":"IPWOQKNWOGX9FLTGMXUSYNDTPKRCTPVMVLOPLINAHYVHAIHEBXHYYDBCZZZWMPDVKGGC9JYSD9VU99999","public_chain":"IOTA_TESTNET_IOTA_TESTNET_NETWORK","prev_hash":"a62acde68924c11d81838185b67801d71ebb1eb0bf9e6ab8e037ab9b57938ea1f67921a25f1204872fdbb557d407a5ea5d0551745c56b881e32eef7bfc034451","type":"PUBLIC_CHAIN"}},{"label":"PUBLIC_CHAIN","properties":{"timestamp":"2019-12-11T10:23:07.442Z","hash":"db57b19d67e11ac2668ff7b43a1a6c5da350c4848fac46feef5834d3dea3f4b3","public_chain":"ETHEREUM_TESTNET_RINKEBY_TESTNET_NETWORK","prev_hash":"a62acde68924c11d81838185b67801d71ebb1eb0bf9e6ab8e037ab9b57938ea1f67921a25f1204872fdbb557d407a5ea5d0551745c56b881e32eef7bfc034451","type":"PUBLIC_CHAIN"}}]}
```
4. Test UPP and include blockchain anchoring window (left and right anchoring):
```bash
curl -d '3W2pCWFB+v3tkJ5p2+QlQDWS5Dsj3QzaphA4ZeX/3Ss=' https://verify.dev.ubirch.com/api/upp/verify/record
{"upp":"liPEEESNtd1lZE99r65GMl243//EQGhY892X0oEeGMvEmUhHwShBe3kbEHgA1E/+38+nLhhtt8DqfXVzQcpPkkUXWRn293RcwDoTuAlLEoonExMmnYcAxCDdbakJYUH6/e2Qnmnb5CVANZLkOyPdDNqmEDhl5f/dK8RAr56JvcayQvTMPX2sM4p4If2uzC7HL0VGTVE0jHl/3Q2qkscyFfvYfdHbUn2RFY+aheCqlXVlSQ98H0KCgJmqkQ==","prev":"liPEEESNtd1lZE99r65GMl243//EQNCpfVGMZLzmX4lu9rVxwIUTzqKEiCU257SUtpZa0dRGtuuFyn1xuXmpSawbKxoEXbVQOCgGDFk1Tp3ShMF2gFUAxCBRW/4r/YTyLHa/VuaGWyKQ8LMA8B3NrTnWv5r8qS7Y5cRAaFjz3ZfSgR4Yy8SZSEfBKEF7eRsQeADUT/7fz6cuGG23wOp9dXNByk+SRRdZGfb3dFzAOhO4CUsSiicTEyadhw==","anchors":{"upper_blockchains":[{"label":"PUBLIC_CHAIN","properties":{"timestamp":"2019-12-11T10:22:55.994Z","hash":"IPWOQKNWOGX9FLTGMXUSYNDTPKRCTPVMVLOPLINAHYVHAIHEBXHYYDBCZZZWMPDVKGGC9JYSD9VU99999","public_chain":"IOTA_TESTNET_IOTA_TESTNET_NETWORK","prev_hash":"a62acde68924c11d81838185b67801d71ebb1eb0bf9e6ab8e037ab9b57938ea1f67921a25f1204872fdbb557d407a5ea5d0551745c56b881e32eef7bfc034451","type":"PUBLIC_CHAIN"}},{"label":"PUBLIC_CHAIN","properties":{"timestamp":"2019-12-11T10:23:07.442Z","hash":"db57b19d67e11ac2668ff7b43a1a6c5da350c4848fac46feef5834d3dea3f4b3","public_chain":"ETHEREUM_TESTNET_RINKEBY_TESTNET_NETWORK","prev_hash":"a62acde68924c11d81838185b67801d71ebb1eb0bf9e6ab8e037ab9b57938ea1f67921a25f1204872fdbb557d407a5ea5d0551745c56b881e32eef7bfc034451","type":"PUBLIC_CHAIN"}}],"lower_blockchains":[{"label":"PUBLIC_CHAIN","properties":{"timestamp":"2019-12-11T10:22:07.440Z","hash":"f13b22446256628282fb9cfcb2d163c1dc2e24c1b6f573250279644a7ced1590","public_chain":"ETHEREUM_TESTNET_RINKEBY_TESTNET_NETWORK","prev_hash":"8d532551a50d47c756787651ae1fc04fb19acaef41939294682b8b049bdce1ff89bded8b4dd1685fe66764459ecc7e927bd7d8be7528eb0354cd6d5eb50a15c3","type":"PUBLIC_CHAIN"}},{"label":"PUBLIC_CHAIN","properties":{"timestamp":"2019-12-11T10:21:48.781Z","hash":"9RISCWMJPMAOWXBSUBHIQBMKOHWEVJDDVQA9BHTGZOKU9MWISUTBVQHSAVV9RSIUAZDFCDMYCPYBZ9999","public_chain":"IOTA_TESTNET_IOTA_TESTNET_NETWORK","prev_hash":"8d532551a50d47c756787651ae1fc04fb19acaef41939294682b8b049bdce1ff89bded8b4dd1685fe66764459ecc7e927bd7d8be7528eb0354cd6d5eb50a15c3","type":"PUBLIC_CHAIN"}}]}}
```

# Issues

- The Sequans modem seems to have an issue if the send interval is longer than 30s. It gets into a state
  where it does not recognize the SIM commands anymore. A solution could be (also from a point of view to
  save energy) is to completely disable the modem and connection and restart it.