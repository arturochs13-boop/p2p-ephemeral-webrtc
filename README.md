# p2p-ephemeral-webrtc

Serverless, zero-persistence P2P WebRTC signaling and an ECDH/AES-GCM encrypted messaging core in
TypeScript.

Two peers derive a shared secret from fresh ECDH P-256 key pairs, exchange only public keys through
an untrusted relay, and then talk directly over an encrypted WebRTC data channel. The relay keeps
room membership in memory for a bounded TTL and stores nothing — no database, no KV, no logs of
payloads.

---

## Architecture

```
    peer A                     edge relay (Durable Object)                    peer B
  ┌────────┐                    ┌──────────────────────┐                    ┌────────┐
  │ ECDH   │   hello {pub A}    │  room token (opaque) │   hello {pub B}    │ ECDH   │
  │ P-256  │ ─────────────────▶ │  max 2 peers         │ ─────────────────▶ │ P-256  │
  │ keygen │ ◀───────────────── │  idle TTL, memory    │ ◀───────────────── │ keygen │
  └───┬────┘   offer / answer   │  only, no storage    │   ice candidates   └───┬────┘
      │        ice candidates   └──────────────────────┘                       │
      │                                                                        │
      │        ┌──────────────── WebRTC data channel (DTLS) ────────────────┐  │
      └───────▶│  AES-GCM-256 frames: { iv, ciphertext }  (direct P2P)      │◀─┘
               └────────────────────────────────────────────────────────────┘
```

The relay only ever sees SDP, ICE candidates, and public keys. Message contents never reach it: after
the handshake, ciphertext flows over the peer-to-peer data channel, not the signaling socket.

### Key schedule

1. Each peer runs `generateEphemeralKeyPair()` — ECDH P-256, extractable public key, non-extractable
   private key, generated fresh per session and garbage-collected with it.
2. Public keys travel as JWKs in `hello` messages.
3. Both sides compute the raw ECDH secret, then HKDF-SHA-256 with:
   - **salt** = `SHA-256(sorted(raw public key A, raw public key B))`
   - **info** = `"p2p-ephemeral-webrtc/v1 aes-gcm-256"`
   - **output** = a non-extractable AES-GCM-256 key
4. The salt is symmetric by construction, so no extra round trip is needed. The same digest is the
   session transcript and is exposed as a six-byte `verificationCode` for out-of-band comparison.

Every message uses a fresh 96-bit random IV from `crypto.getRandomValues`. Frames are
`{"iv":"<base64>","ciphertext":"<base64>"}`; the GCM tag is appended to the ciphertext and the IV is
authenticated. Decryption rejects a wrong key, a modified ciphertext, a modified IV, and optional
additional authenticated data that does not match.

---

## Threat model

| Adversary capability | Mitigation |
| --- | --- |
| Reads signaling traffic | Only public keys, SDP, and ICE candidates are sent; message bodies are never relayed. |
| Modifies signaling traffic | Tampered SDP/candidates fail validation or negotiation; tampered `hello` keys change the derived key, so the first encrypted message fails authentication. |
| Replays a signaling frame | The relay drops payloads when no counterpart is attached and never buffers them; session keys are fresh per session. |
| Reads relay memory | The relay holds sockets and a token only, never message contents, and only while the room is live. |
| Reconnects to an old room | Rooms expire after an idle TTL, sockets are closed, and process exit destroys all state. |
| Forges an encrypted frame | AES-GCM-256 with a 128-bit tag; forgery requires the session key. |
| Reuses an IV | Random 96-bit IV per message; a 200-message uniqueness test guards the path. |

**Out of scope.** The relay does not authenticate peer identities: possession of the room token is
the only admission check, which is why the token must be unguessable and shared out of band. For
identity binding, compare `verificationCode` between users (or pin public keys) before trusting a
session. Compromised endpoints and traffic analysis of endpoints are also out of scope.

The signaling channel is assumed to preserve message order per connection (WebSocket semantics); the
handshake relies on `hello` arriving before `offer`/`answer`.

---

## Modules

| File | Responsibility |
| --- | --- |
| `src/crypto.ts` | ECDH P-256, HKDF-SHA-256, AES-GCM-256, base64, frame serialization. |
| `src/signaling-worker.ts` | In-memory room registry with TTL, plus the Cloudflare Worker/Durable Object adapter. |
| `src/peer-session.ts` | Peer connection state machine, handshake, data-channel wiring, send queue, verification code. |
| `tests/crypto.test.ts` | Key agreement, tamper rejection, IV uniqueness, framing, base64 edge cases. |
| `tests/signaling.test.ts` | Pairing, capacity, TTL expiry, presence, oversized payloads. |

### Session lifecycle

```
idle ──start()──▶ handshaking ──hello/offer/answer──▶ connecting ──datachannel open──▶ connected
                        │                                  │                              │
                        └──────────── failure ─────────────┴──────────────▶ failed ──▶ closed
```

`send()` before `connected` queues up to `maxQueuedMessages` (default 64) and flushes in order when
the channel opens; the queue is bounded so a stalled connection cannot exhaust memory. Any protocol
error, decryption failure, or connection failure moves the session to `failed` and reports through
`onError`.

---

## Quick start

```bash
npm install
npm test            # builds and runs 26 node:test cases
npx tsc --noEmit    # strict type check
```

Library usage:

```ts
import { generateEphemeralKeyPair, deriveSessionKeys, encryptMessage, decryptMessage } from "./src/crypto.js";

const alice = await generateEphemeralKeyPair();
const bob = await generateEphemeralKeyPair();

// Exchange public keys over any channel, then:
const aliceKeys = await deriveSessionKeys(alice, await exportPublicKey(bob.publicKey));
const bobKeys = await deriveSessionKeys(bob, await exportPublicKey(alice.publicKey));

const frame = await encryptMessage(aliceKeys.key, "hello over an untrusted link");
console.log(await decryptMessage(bobKeys.key, frame)); // "hello over an untrusted link"
```

Session usage:

```ts
import { PeerSession } from "./src/peer-session.js";

const session = new PeerSession({
  peerId: "peer_alice01",
  remotePeerId: "peer_bob0002",
  initiator: true,
  transport,                     // your WebSocket wrapper implementing SignalingTransport
  onMessage: (text) => console.log(text),
  onStateChange: (state) => console.log("state:", state),
});

await session.start();
await session.send("encrypted once the channel opens");
```

---

## Deploying the relay

`wrangler.toml` binds the worker to a Durable Object namespace, so each room token maps to one
instance and both sockets land in the same isolate — that is what makes purely in-memory room state
correct at the edge.

```bash
npx wrangler deploy
```

Endpoints:

- `GET /health` — liveness probe, returns `{"ok":true}`.
- `GET /signal?room=<token>&peer=<id>` with `Upgrade: websocket` — joins the room and relays frames
  between the two peers.
- `GET /signal` without an upgrade or with missing parameters — `426` / `400` JSON errors.

Room tokens must match `^[A-Za-z0-9_-]{8,128}$`; generate them with at least 128 bits of randomness.
Signaling payloads are capped at 64 KiB. Rooms idle out after 120 seconds, and the Durable Object
sweeps expired rooms every 15 seconds.

To run without Cloudflare, instantiate `SignalingRelay` inside any single-process WebSocket server;
the room semantics are identical. A multi-instance deployment needs a shared rendezvous point (this
is exactly what the Durable Object provides).

---

## Design notes

- **Standard library only.** No crypto dependencies: Web Crypto is available in browsers, Node 20+,
  and Workers.
- **Zero persistence by construction.** The relay has no storage binding, no disk writes, and no
  logging of payloads. `SignalingRelay` exposes `sweep()` and `dispose()` so shutdown is explicit.
- **Strict inputs.** Signaling payloads are validated by shape and type before use; malformed frames
  fail closed rather than being partially applied.
- **Bounded resources.** Two peers per room, 64 KiB per signaling frame, bounded send queue, TTL on
  every room.
- **Typed without vendor lock-in.** The Workers adapter declares the minimal socket/namespace surface
  it uses, so the package compiles with plain `@types/node` and DOM types.

---

## License

MIT
