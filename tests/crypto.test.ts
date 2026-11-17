import assert from "node:assert/strict";
import test from "node:test";

import {
  IV_BYTES,
  decryptMessage,
  deriveSessionKeys,
  encryptMessage,
  exportPublicKey,
  fromBase64,
  generateEphemeralKeyPair,
  importPublicKey,
  parseFrame,
  serializeFrame,
  toBase64,
  type SessionKeys,
} from "../src/crypto.js";

interface Party {
  readonly keys: SessionKeys;
  readonly peerPublic: JsonWebKey;
}

async function establish(): Promise<{ alice: Party; bob: Party }> {
  const alicePair = await generateEphemeralKeyPair();
  const bobPair = await generateEphemeralKeyPair();
  const alicePublic = await exportPublicKey(alicePair.publicKey);
  const bobPublic = await exportPublicKey(bobPair.publicKey);

  const alice = await deriveSessionKeys(alicePair, bobPublic);
  const bob = await deriveSessionKeys(bobPair, alicePublic);

  return {
    alice: { keys: alice, peerPublic: bobPublic },
    bob: { keys: bob, peerPublic: alicePublic },
  };
}

test("both peers derive the same AES-GCM key and transcript", async () => {
  const { alice, bob } = await establish();
  assert.deepEqual(alice.keys.transcript, bob.keys.transcript);
  assert.equal(alice.keys.key.algorithm.name, "AES-GCM");
  assert.equal((alice.keys.key.algorithm as AesKeyAlgorithm).length, 256);
  assert.deepEqual(alice.keys.key.usages.slice().sort(), ["decrypt", "encrypt"]);
});

test("alice can decrypt what bob encrypts and vice versa", async () => {
  const { alice, bob } = await establish();

  const fromBob = await encryptMessage(bob.keys.key, "handshake complete");
  assert.equal(await decryptMessage(alice.keys.key, fromBob), "handshake complete");

  const fromAlice = await encryptMessage(alice.keys.key, "acknowledged");
  assert.equal(await decryptMessage(bob.keys.key, fromAlice), "acknowledged");
});

test("empty and unicode payloads survive the round trip", async () => {
  const { alice, bob } = await establish();
  const payloads = ["", "ñandú 🐦 中文 \u0000 null", "line one\nline two\r\n"];

  for (const payload of payloads) {
    const frame = await encryptMessage(alice.keys.key, payload);
    assert.equal(await decryptMessage(bob.keys.key, frame), payload);
  }
});

test("a third party cannot decrypt a session frame", async () => {
  const { alice } = await establish();
  const { alice: mallory } = await establish();

  const frame = await encryptMessage(alice.keys.key, "confidential");
  await assert.rejects(() => decryptMessage(mallory.keys.key, frame));
});

test("tampering with the ciphertext is rejected", async () => {
  const { alice, bob } = await establish();
  const frame = await encryptMessage(alice.keys.key, "transfer 100 units");

  const bytes = fromBase64(frame.ciphertext);
  bytes[bytes.length - 1] = (bytes[bytes.length - 1] ?? 0) ^ 0x01;
  const tampered = { iv: frame.iv, ciphertext: toBase64(bytes) };

  await assert.rejects(() => decryptMessage(bob.keys.key, tampered));
});

test("tampering with the initialization vector is rejected", async () => {
  const { alice, bob } = await establish();
  const frame = await encryptMessage(alice.keys.key, "bind me to an iv");

  const iv = fromBase64(frame.iv);
  iv[0] = (iv[0] ?? 0) ^ 0xff;
  const tampered = { iv: toBase64(iv), ciphertext: frame.ciphertext };

  await assert.rejects(() => decryptMessage(bob.keys.key, tampered));
});

test("a frame with a non-96-bit iv is rejected before decryption", async () => {
  const { alice, bob } = await establish();
  const frame = await encryptMessage(alice.keys.key, "short iv");
  const shortIv = { iv: toBase64(new Uint8Array(8)), ciphertext: frame.ciphertext };

  await assert.rejects(() => decryptMessage(bob.keys.key, shortIv), /initialization vector/);
});

test("additional authenticated data must match", async () => {
  const { alice, bob } = await establish();
  const frame = await encryptMessage(alice.keys.key, "room-scoped", "room-alpha");

  assert.equal(await decryptMessage(bob.keys.key, frame, "room-alpha"), "room-scoped");
  await assert.rejects(() => decryptMessage(bob.keys.key, frame, "room-beta"));
  await assert.rejects(() => decryptMessage(bob.keys.key, frame));
});

test("every message uses a fresh 96-bit iv", async () => {
  const { alice } = await establish();
  const seen = new Set<string>();

  for (let index = 0; index < 200; index += 1) {
    const frame = await encryptMessage(alice.keys.key, `message ${index}`);
    const iv = fromBase64(frame.iv);
    assert.equal(iv.length, IV_BYTES);
    assert.equal(seen.has(frame.iv), false, "iv reused");
    seen.add(frame.iv);
  }
  assert.equal(seen.size, 200);
});

test("frames serialize to JSON and parse back", async () => {
  const { alice, bob } = await establish();
  const frame = await encryptMessage(alice.keys.key, "wire format");
  const parsed = parseFrame(serializeFrame(frame));
  assert.deepEqual(parsed, frame);
  assert.equal(await decryptMessage(bob.keys.key, parsed), "wire format");
});

test("malformed frames are rejected", () => {
  assert.throws(() => parseFrame("not json"), /not JSON/);
  assert.throws(() => parseFrame("[]"), /expected an object/);
  assert.throws(() => parseFrame('{"iv":1,"ciphertext":"AA=="}'), /must be strings/);
  assert.throws(() => parseFrame('{"iv":"AA=="}'), /must be strings/);
});

test("generated public keys are exportable and import cleanly", async () => {
  const pair = await generateEphemeralKeyPair();
  const jwk = await exportPublicKey(pair.publicKey);

  assert.equal(jwk.kty, "EC");
  assert.equal(jwk.crv, "P-256");
  assert.equal(jwk.d, undefined, "private scalar must never be exported");

  const imported = await importPublicKey(jwk);
  assert.equal(imported.type, "public");
  assert.equal(imported.algorithm.name, "ECDH");
});

test("public keys are rejected when the key material is invalid", async () => {
  await assert.rejects(() => importPublicKey({ kty: "EC", crv: "P-256", x: "!!", y: "!!" }));
  await assert.rejects(() => importPublicKey({ kty: "EC", crv: "P-384", x: "", y: "" }));
});

test("base64 round-trips arbitrary byte strings", () => {
  for (let length = 0; length < 40; length += 1) {
    const bytes = crypto.getRandomValues(new Uint8Array(length));
    assert.deepEqual(fromBase64(toBase64(bytes)), bytes);
  }
});

test("base64 decoding rejects non-canonical input", () => {
  assert.throws(() => fromBase64("abc"), /multiple of four/);
  assert.throws(() => fromBase64("ab!d"), /invalid base64 character/);
});
