module aiguard

go 1.26.0

replace github.com/tailscale/wf => ./third_party/wf

require (
	github.com/Microsoft/go-winio v0.6.2
	github.com/tailscale/wf v0.0.0-00010101000000-000000000000
	github.com/tc-hib/winres v0.3.1
	github.com/wailsapp/wails/v3 v3.1.0
	golang.org/x/image v0.45.0
	golang.org/x/sys v0.50.0
	golang.zx2c4.com/wireguard/windows v1.1.1
)

require (
	github.com/coder/websocket v1.8.14 // indirect
	github.com/ebitengine/purego v0.11.1 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/nfnt/resize v0.0.0-20180221191011-83c6a9932646 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/term v0.46.0 // indirect
)
