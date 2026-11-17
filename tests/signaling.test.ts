import assert from "node:assert/strict";
import test from "node:test";

import {
  MAX_PEERS_PER_ROOM,
  MAX_SIGNAL_BYTES,
  SignalingError,
  SignalingRelay,
  SignalingRoom,
  type PeerSocket,
} from "../src/signaling-worker.js";

class FakeSocket implements PeerSocket {
  readonly sent: string[] = [];
  closed: { code: number | undefined; reason: string | undefined } | undefined;

  send(data: string): void {
    if (this.closed !== undefined) {
      throw new Error("socket is closed");
    }
    this.sent.push(data);
  }

  close(code?: number, reason?: string): void {
    this.closed = { code, reason };
  }
}

const ROOM = "room_abcdef1234";
const ALICE = "peer_alice01";
const BOB = "peer_bob0002";
const CAROL = "peer_carol03";

test("two peers pair and exchange opaque signaling payloads", () => {
  const relay = new SignalingRelay();
  const alice = new FakeSocket();
  const bob = new FakeSocket();

  relay.join(ROOM, ALICE, alice);
  relay.join(ROOM, BOB, bob);

  assert.deepEqual(JSON.parse(alice.sent[0] ?? ""), { type: "presence", action: "joined", peerId: BOB });
  assert.equal(bob.sent.length, 0);

  assert.equal(relay.relay(ROOM, ALICE, '{"type":"offer","sdp":"v=0"}'), true);
  assert.deepEqual(bob.sent, ['{"type":"offer","sdp":"v=0"}']);
  assert.equal(alice.sent.length, 1, "sender does not receive its own payload");

  assert.equal(relay.relay(ROOM, BOB, '{"type":"answer"}'), true);
  assert.equal(alice.sent[1], '{"type":"answer"}');
});

test("a third peer is rejected once the room is full", () => {
  const relay = new SignalingRelay();
  relay.join(ROOM, ALICE, new FakeSocket());
  relay.join(ROOM, BOB, new FakeSocket());

  assert.throws(
    () => relay.join(ROOM, CAROL, new FakeSocket()),
    (error: unknown) => error instanceof SignalingError && error.code === "room-full",
  );
  assert.equal(MAX_PEERS_PER_ROOM, 2);
});

test("duplicate peer ids are rejected", () => {
  const relay = new SignalingRelay();
  relay.join(ROOM, ALICE, new FakeSocket());

  assert.throws(
    () => relay.join(ROOM, ALICE, new FakeSocket()),
    (error: unknown) => error instanceof SignalingError && error.code === "duplicate-peer",
  );
});

test("relay before the counterpart joins is dropped, never buffered", () => {
  const room = new SignalingRoom(ROOM);
  const alice = new FakeSocket();
  room.join(ALICE, alice);

  assert.equal(room.relay(ALICE, "early"), false);
  assert.equal(alice.sent.length, 0);
});

test("an unattached sender is rejected without echoing its payload", () => {
  const relay = new SignalingRelay();
  relay.join(ROOM, ALICE, new FakeSocket());

  assert.throws(
    () => relay.relay(ROOM, BOB, "spoof"),
    (error: unknown) => error instanceof SignalingError && error.code === "unknown-peer",
  );
});

test("idle rooms expire and their sockets are closed", () => {
  let now = 1_000;
  const relay = new SignalingRelay({ ttlMs: 5_000, now: () => now });
  const alice = new FakeSocket();
  relay.join(ROOM, ALICE, alice);

  now = 5_999;
  assert.equal(relay.getRoom(ROOM)?.size, 1);

  now = 6_000;
  assert.equal(relay.getRoom(ROOM), undefined);
  assert.deepEqual(alice.closed, { code: 1000, reason: "room expired" });
  assert.equal(relay.size, 0);
});

test("activity extends the room ttl", () => {
  let now = 0;
  const relay = new SignalingRelay({ ttlMs: 1_000, now: () => now });
  const alice = new FakeSocket();
  const bob = new FakeSocket();
  relay.join(ROOM, ALICE, alice);

  now = 900;
  relay.join(ROOM, BOB, bob);
  now = 1_500;

  assert.equal(relay.getRoom(ROOM)?.size, 2);

  now = 1_901;
  assert.equal(relay.sweep(), 1);
  assert.equal(relay.size, 0);
});

test("expired rooms reject stale relays and allow a fresh room under the same token", () => {
  let now = 0;
  const relay = new SignalingRelay({ ttlMs: 100, now: () => now });
  const alice = new FakeSocket();
  relay.join(ROOM, ALICE, alice);
  now = 100;

  assert.throws(
    () => relay.relay(ROOM, ALICE, "late"),
    (error: unknown) => error instanceof SignalingError && error.code === "room-expired",
  );
  assert.equal(alice.closed?.code, 1000);

  const bob = new FakeSocket();
  relay.join(ROOM, BOB, bob);
  assert.equal(relay.getRoom(ROOM)?.peers().join(","), BOB);
});

test("the last peer leaving destroys the room", () => {
  const relay = new SignalingRelay();
  const alice = new FakeSocket();
  const bob = new FakeSocket();
  relay.join(ROOM, ALICE, alice);
  relay.join(ROOM, BOB, bob);

  relay.leave(ROOM, ALICE);
  assert.equal(relay.size, 1);
  assert.deepEqual(JSON.parse(bob.sent[0] ?? ""), { type: "presence", action: "left", peerId: ALICE });

  relay.leave(ROOM, BOB);
  assert.equal(relay.size, 0);
  assert.equal(alice.closed, undefined, "a peer that already left is not closed again");
});

test("oversized or invalid signaling input is rejected", () => {
  const room = new SignalingRoom(ROOM);
  const alice = new FakeSocket();
  const bob = new FakeSocket();
  room.join(ALICE, alice);
  room.join(BOB, bob);

  assert.throws(
    () => room.relay(ALICE, "x".repeat(MAX_SIGNAL_BYTES + 1)),
    (error: unknown) => error instanceof SignalingError && error.code === "payload-too-large",
  );
  assert.throws(() => new SignalingRoom("short"), /room token/);
  assert.throws(() => room.join("bad id with spaces", new FakeSocket()), /peer id/);
});

test("expiring a room is idempotent and clears membership", () => {
  const room = new SignalingRoom(ROOM);
  const alice = new FakeSocket();
  room.join(ALICE, alice);

  room.expire();
  room.expire();

  assert.equal(room.isClosed, true);
  assert.equal(room.size, 0);
  assert.deepEqual(alice.closed, { code: 1000, reason: "room expired" });
});
