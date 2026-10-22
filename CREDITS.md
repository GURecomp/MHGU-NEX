# Credits, licenses and disclaimers

## Credits
MHGU-NEX is an independent Python reimplementation of a NEX (PRUDP Lite) server for Monster Hunter Generations Ultimate. Protocol formats and behaviour were derived from, and verified against:

| Project | License | Used for |
|---|---|---|
| [NextendoNetwork/nextendo-nex](https://github.com/NextendoNetwork/nextendo-nex) | PolyForm Shield 1.0.0 | PRUDP Lite framing, endpoint, ticket and matchmaking behaviour |
| [NextendoNetwork/citron-nextendo](https://github.com/NextendoNetwork/citron-nextendo) | GPL-3.0 | Emulator-side reference for talking to a NEX server |
| [PretendoNetwork/monster-hunter-4-ultimate](https://github.com/PretendoNetwork/monster-hunter-4-ultimate) | AGPL-3.0 | Reference for the MH4U game-server design only. No code copied |

## License notes
- **nextendo-nex** is under the [PolyForm Shield License 1.0.0](https://polyformproject.org/licenses/shield/1.0.0). Anyone who receives a copy of software derived from it must get these terms or that URL, and it may not be used to provide a product that competes with the licensor's. This project is a personal, non-commercial, self-hosted tool.
- The emulator-side changes live in a fork of suyu (GPL-3.0). Distributing a build requires GPL-3.0 compliance and a source offer.
- This repository has no license file yet. Add the license you choose for your own code, keeping it compatible with the terms above.

## Disclaimers
- The server never contacts Nintendo or Nextendo servers, and has no logins or authentication. It only serves clients that you point at it.
- Monster Hunter is a trademark of Capcom. Nintendo and Nextendo are not affiliated with this project.
- No game files, keys or copyrighted assets are included. You must supply your own legally obtained copy of the game.
