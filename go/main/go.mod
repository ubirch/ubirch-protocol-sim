module main

go 1.12

require (
	github.com/creack/goselect v0.1.0 // indirect
	github.com/google/uuid v1.1.1
	github.com/ubirch/ubirch-protocol-sim/go/ubirch v0.0.0
	go.bug.st/serial.v1 v0.0.0-20180827123349-5f7892a7bb45
	golang.org/x/sys v0.0.0-20190813064441-fde4db37ae7a // indirect
)

replace github.com/ubirch/ubirch-protocol-sim/go/ubirch => ../ubirch
