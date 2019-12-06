![ubirch logo](https://ubirch.de/wp-content/uploads/2018/10/cropped-uBirch_Logo.png)

# ubirch-protocol on a SIM

This repository contains example code, how to use the [ubirch-protocol](//github.com/ubirch/ubirch-protocol) 
in conjunction with the SIM application (SIGNiT) by 
[G+D (Giesecke+Devrient)](//www.gi-de.com/) and [ubirch GmbH](//ubirch.com/). The SIM card application wraps the required
functionality to run the ubirch-protocol on any (embedded) device that has access to a 
modem or smart card capabilities.

The requirement is an interface that can send APDU commands to the SIM card application. 
This most often will be a modem that supports the standard `AT+CSIM` command (3GPP TS 27.007).

- [SIGNiT Customer Manual](docs/SIGNiT%20Customer%20Manual%20v3.pdf) (PDF)
- [Micropython Example Code](micropython/ubirch/ubirch_sim.py) (.py)

### Requirements

- a SIM card with the ubirch applet installed
- a Modem that supports the AT+CSIM commands to send APDU commands to the SIM card
- connectivity

## Key Generation

Generating a key, always use the UUID as the title of the key entry and use the key ID
to access the key (signing key and verifying key need two different IDs!). The UUID will
be automatically placed into the [UPP](//github.com/ubirch/ubirch-protocol#basic-message-format)
as the required identity id.

## Signing/Chaining messages

The optimal way to work with the ubirch-protocol is to hash the actual data you want to
send and use the responding bytes as the payload of the [UPP](//github.com/ubirch/ubirch-protocol#basic-message-format).
This hash can be used as a key to identify the message on the server side. The hash must
be unique per messages, it should optimally contain a sequence number or timestamp.

# Examples
 
While it is possible to implement the full protocol without the need for additional
code, we have opted to provide an implementation in MicroPython, which can be used on
embedded devices, such as the [Pycom GPy](//pycom.io/product/gpy/).

Additionally, other implementations provide an interface to the SIM application.

### Go

The Go implementation can be compiled and cross compiled to a number of architectures.
This example also has a little micropython proxy that can be installed on a Pycom GPy or FiPy,
so it can be used instead of a directly connected modem.

### MicroPython

The MicroPython implementation can be loaded on any GPy device and will do the following
steps:

> Currently the generation will only work with Pycom devices, if the key ID is only
> 1 (one) byte long. This is due to a buffer length issue with the underlying python
> implementation.

1. Initialize the SIM card and unlock the application with a PIN code.
2. Generate a new key pair and store it on the SIM card (fails if already generated).
3. Register the generated public key with the ubirch key server.
4. Create a signed [UPP](//github.com/ubirch/ubirch-protocol#basic-message-format) from some data (`{"ts":1234,"data":"random"}`).
5. Send the signed message to the ubirch backend (`https://niomon.demo.ubirch.com`).
6. Verify the signed [UPP](//github.com/ubirch/ubirch-protocol#basic-message-format) by feeding it back to the SIM card application.

TODO:

- Verify the [UPP](//github.com/ubirch/ubirch-protocol#basic-message-format) and check blockchain anchoring (`//niomon.demo.ubirch.com/api/verify`)*

> __*__ Sending data to the ubirch backend requires an API token. 

# LICENSE

```
Copyright 2019 ubirch GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
