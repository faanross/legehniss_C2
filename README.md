## Work-in-Progress VS 2
Multi-Modal C2 Simulator with 3 gears.

### Gear 1
- DNS as heartbeat
- Server->Agent Z-value as state machine (DNS Sandwich), AND/OR
- Server->Agent non-conventional qClass value provides uint16 (0 - 65535) options
- Server->Agent data using TXT (Joker ScreenMate)
- Agent -> Server data via stego/QR uploaded to GH/imgur (TBD)
Goal of gear 1 is stealth + to determine whether to switch to gear 2 which represents higher degree of risk in exchange for higher degree of operational efficiency. Obviously inspired by SUNBURST.

### Gear 2
- HTTPS to allow for higher degree of bidirectional data transfer
- Simple: GET checkin, POST data from agent (encoded JSON in body)
Then, if an even higher degree of risk is willing to be assumed for highest degree of operational efficiency, allows for transition to WS Secure channel.

### Gear 3
- WebSockets Secure allows for server to PUSH commands, no longer hampered by R+R model
This is a WIP at present