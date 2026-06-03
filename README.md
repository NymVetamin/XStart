# XStart

Windows GUI launcher for Xray VLESS profiles.

## Features

- Import profiles from a `vless://` link.
- Import profiles from a full Xray JSON config that contains a VLESS outbound.
- Start and stop local `xray.exe`.
- Local SOCKS proxy on `127.0.0.1:10808`.
- Optional Windows TUN mode for routing machine traffic through Xray.
- Download official Xray-core releases and Wintun with hash checks.

## Runtime Files

Keep these files next to `XStart.exe`:

- `xray.exe`
- `geoip.dat`
- `geosite.dat`
- `wintun.dll` for TUN mode

The app can download `xray.exe`, `geoip.dat`, `geosite.dat`, and `wintun.dll` through the `Download core` button.

## TUN Mode

Xray `v26.3.27` creates the Wintun adapter but does not apply Windows routes itself. XStart prepares the required Windows routing:

- a precise host route to the proxy endpoint through the physical network;
- DNS and interface metric for `xstart0`;
- `0.0.0.0/0` and `::/0` routes through `xstart0`;
- cleanup of the routes on stop or failed start.

TUN mode usually requires running XStart as administrator.
