module agent

go 1.22.2

replace golang.org/x/crypto => github.com/golang/crypto v0.24.0

replace golang.org/x/sys => github.com/golang/sys v0.21.0

replace golang.org/x/net => github.com/golang/net v0.26.0

replace golang.org/x/time => github.com/golang/time v0.5.0

replace golang.org/x/sync => github.com/golang/sync v0.7.0

replace golang.org/x/text => github.com/golang/text v0.16.0

replace golang.org/x/exp => github.com/golang/exp v0.0.0-20240604190554-fc45aab8b7f8

require (
	github.com/anacrolix/torrent v1.56.1
	github.com/gorilla/websocket v1.5.3 // indirect
	golang.org/x/crypto v0.0.0-00010101000000-000000000000 // indirect
	golang.org/x/sys v0.21.0 // indirect
)
