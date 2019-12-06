# Micropython Example

Works on a Pycom GPy module.

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