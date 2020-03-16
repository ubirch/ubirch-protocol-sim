module github.com/ubirch/ubirch-protocol-sim/go/main

go 1.12

require (
	github.com/creack/goselect v0.1.1 // indirect
	github.com/google/uuid v1.1.1
	github.com/ubirch/ubirch-protocol-sim/go/ubirch v0.0.0
	go.bug.st/serial.v1 v0.0.0-20191202182710-24a6610f0541
	golang.org/x/sys v0.0.0-20200302150141-5c8b2ff67527 // indirect
)

replace github.com/ubirch/ubirch-protocol-sim/go/ubirch => ../ubirch
