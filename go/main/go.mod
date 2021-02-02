module github.com/ubirch/ubirch-protocol-sim/go/main

go 1.12

require (
	github.com/google/uuid v1.1.1
	github.com/sirupsen/logrus v1.7.0
	github.com/ubirch/ubirch-protocol-sim/go/ubirch v0.0.0
	go.bug.st/serial v1.1.0
	golang.org/x/sys v0.0.0-20200302150141-5c8b2ff67527 // indirect
)

replace github.com/ubirch/ubirch-protocol-sim/go/ubirch => ../ubirch
