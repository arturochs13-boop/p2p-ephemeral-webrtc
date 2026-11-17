/**
 * Zero-persistence signaling relay for ephemeral WebRTC sessions.
 *
 * The relay only ever holds room state in memory: a room is a token, the sockets currently
 * attached to it, and an expiry timestamp. Nothing is written to disk, KV, D1, or any other
 * storage, and every room is destroyed with its isolate or when its TTL elapses.
 *
 * `SignalingRelay` is the portable core and is what tests exercise. `SignalingDurableObject` is
 * the Cloudflare adapter: one Durable Object instance owns one room so that a pair of WebSockets
 * lands in the same isolate, which is what makes in-memory room state correct at the edge.
 */

/** Default idle lifetime of a room. */
export const DEFAULT_ROOM_TTL_MS = 120_000;

/** Maximum payload accepted from a peer, in bytes of UTF-8. SDP offers comfortably fit. */
export const MAX_SIGNAL_BYTES = 64 * 1024;

/** A room pairs exactly two peers. */
export const MAX_PEERS_PER_ROOM = 2;

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{8,128}$/;

/** The minimal socket surface the relay needs; implemented by the Durable Object adapter. */
export interface PeerSocket {
  send(data: string): void;
  close(code?: number, reason?: string): void;
}

/** Error codes surfaced to callers and mapped to HTTP status codes by the adapter. */
export type SignalingErrorCode =
  | "invalid-room"
  | "invalid-peer"
  | "room-full"
  | "room-expired"
  | "duplicate-peer"
  | "unknown-peer"
  | "payload-too-large";

/** A protocol-level rejection. Messages never contain peer payloads. */
export class SignalingError extends Error {
  constructor(
    readonly code: SignalingErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "SignalingError";
  }
}

export interface RoomOptions {
  readonly ttlMs?: number;
  readonly maxPeers?: number;
  /** Injectable clock; defaults to `Date.now`. */
  readonly now?: () => number;
}

interface RoomMember {
  readonly socket: PeerSocket;
  readonly joinedAt: number;
}

function assertToken(value: string, code: SignalingErrorCode, label: string): void {
  if (!TOKEN_PATTERN.test(value)) {
    throw new SignalingError(code, `${label} must match ${TOKEN_PATTERN.source}`);
  }
}

/**
 * One signaling room, held entirely in memory.
 *
 * Peers join with an opaque id, then exchange signaling messages through `relay`. The room also
 * emits presence notifications so a peer learns when its counterpart connects or leaves. The TTL
 * is idle-based: `join`, `relay`, and `refresh` extend `expiresAt`, and no extension ever exceeds
 * `ttlMs` beyond the last activity.
 */
export class SignalingRoom {
  readonly token: string;
  readonly ttlMs: number;
  readonly maxPeers: number;
  readonly createdAt: number;

  private readonly members = new Map<string, RoomMember>();
  private readonly now: () => number;
  private expiresAtValue: number;
  private closed = false;

  constructor(token: string, options: RoomOptions = {}) {
    assertToken(token, "invalid-room", "room token");
    this.token = token;
    this.ttlMs = options.ttlMs ?? DEFAULT_ROOM_TTL_MS;
    this.maxPeers = options.maxPeers ?? MAX_PEERS_PER_ROOM;
    this.now = options.now ?? (() => Date.now());
    if (!Number.isFinite(this.ttlMs) || this.ttlMs <= 0) {
      throw new RangeError("ttlMs must be a positive finite number");
    }
    if (!Number.isInteger(this.maxPeers) || this.maxPeers < 2) {
      throw new RangeError("maxPeers must be an integer of at least 2");
    }
    this.createdAt = this.now();
    this.expiresAtValue = this.createdAt + this.ttlMs;
  }

  /** Absolute timestamp after which the room is considered expired. */
  get expiresAt(): number {
    return this.expiresAtValue;
  }

  /** Whether the room has been closed by `expire` or `dispose`. */
  get isClosed(): boolean {
    return this.closed;
  }

  /** Number of currently attached peers. */
  get size(): number {
    return this.members.size;
  }

  /** Peer ids in join order. */
  peers(): string[] {
    return [...this.members.keys()];
  }

  /** Whether the room has passed its idle deadline at the supplied (or current) time. */
  isExpired(at: number = this.now()): boolean {
    return this.closed || at >= this.expiresAtValue;
  }

  /** Extends the idle deadline, capped at one TTL beyond the current time. */
  refresh(): void {
    this.expiresAtValue = this.now() + this.ttlMs;
  }

  /** Attaches a peer and notifies the other member. */
  join(peerId: string, socket: PeerSocket): void {
    assertToken(peerId, "invalid-peer", "peer id");
    this.assertUsable();
    if (this.members.has(peerId)) {
      throw new SignalingError("duplicate-peer", `peer ${peerId} is already attached to this room`);
    }
    if (this.members.size >= this.maxPeers) {
      throw new SignalingError("room-full", "room already has its maximum number of peers");
    }
    this.members.set(peerId, { socket, joinedAt: this.now() });
    this.refresh();
    this.broadcast({ type: "presence", action: "joined", peerId }, peerId);
  }

  /** Detaches a peer and notifies the remaining member. */
  leave(peerId: string): void {
    if (!this.members.delete(peerId)) {
      return;
    }
    this.refresh();
    this.broadcast({ type: "presence", action: "left", peerId }, peerId);
  }

  /**
   * Forwards an opaque payload to the other attached peer.
   *
   * The payload is not parsed or logged; only its size and the sender's membership are checked.
   * Returns `false` when no counterpart is attached yet, in which case the caller may choose to
   * drop the message — the relay never buffers it, because buffering would make the relay stateful
   * beyond socket registration.
   */
  relay(fromPeerId: string, payload: string): boolean {
    assertToken(fromPeerId, "invalid-peer", "peer id");
    this.assertUsable();
    if (!this.members.has(fromPeerId)) {
      throw new SignalingError("unknown-peer", `peer ${fromPeerId} is not attached to this room`);
    }
    if (new TextEncoder().encode(payload).length > MAX_SIGNAL_BYTES) {
      throw new SignalingError("payload-too-large", `signaling payload exceeds ${MAX_SIGNAL_BYTES} bytes`);
    }
    this.refresh();
    const recipient = this.counterpartOf(fromPeerId);
    if (recipient === undefined) {
      return false;
    }
    recipient.socket.send(payload);
    return true;
  }

  /** Closes every attached socket and marks the room closed. Safe to call repeatedly. */
  expire(): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    for (const member of this.members.values()) {
      try {
        member.socket.close(1000, "room expired");
      } catch {
        // A socket may already be gone; expiry still succeeds.
      }
    }
    this.members.clear();
  }

  private counterpartOf(peerId: string): RoomMember | undefined {
    for (const [id, member] of this.members) {
      if (id !== peerId) {
        return member;
      }
    }
    return undefined;
  }

  private broadcast(message: Record<string, string>, exceptPeerId: string): void {
    const serialized = JSON.stringify(message);
    for (const [id, member] of this.members) {
      if (id === exceptPeerId) {
        continue;
      }
      try {
        member.socket.send(serialized);
      } catch {
        // A dead socket must not prevent the other peer from joining or leaving.
      }
    }
  }

  private assertUsable(): void {
    if (this.isExpired()) {
      this.expire();
      throw new SignalingError("room-expired", "room has expired");
    }
  }
}

/**
 * In-memory registry of rooms.
 *
 * Used directly by the Durable Object adapter (one registry per room-owning instance) and usable
 * as a single-isolate relay in tests or local development. It never persists anything.
 */
export class SignalingRelay {
  private readonly rooms = new Map<string, SignalingRoom>();
  private readonly options: RoomOptions;

  constructor(options: RoomOptions = {}) {
    this.options = options;
  }

  /** Number of live rooms. */
  get size(): number {
    return this.rooms.size;
  }

  /** Creates a room, or returns the existing live room with the same token. */
  openRoom(token: string): SignalingRoom {
    const existing = this.rooms.get(token);
    if (existing !== undefined && !existing.isExpired()) {
      return existing;
    }
    const room = new SignalingRoom(token, this.options);
    this.rooms.set(token, room);
    return room;
  }

  /** Looks up a live room without creating one. */
  getRoom(token: string): SignalingRoom | undefined {
    const room = this.rooms.get(token);
    if (room === undefined) {
      return undefined;
    }
    if (room.isExpired()) {
      room.expire();
      this.rooms.delete(token);
      return undefined;
    }
    return room;
  }

  /** Joins a peer to a room, creating the room on first use. */
  join(token: string, peerId: string, socket: PeerSocket): SignalingRoom {
    const room = this.openRoom(token);
    room.join(peerId, socket);
    return room;
  }

  /** Relays a payload between the two peers of a room. */
  relay(token: string, fromPeerId: string, payload: string): boolean {
    const room = this.getRoom(token);
    if (room === undefined) {
      throw new SignalingError("room-expired", "room does not exist or has expired");
    }
    return room.relay(fromPeerId, payload);
  }

  /** Detaches a peer, removing the room once it is empty. */
  leave(token: string, peerId: string): void {
    const room = this.rooms.get(token);
    if (room === undefined) {
      return;
    }
    room.leave(peerId);
    if (room.size === 0) {
      room.expire();
      this.rooms.delete(token);
    }
  }

  /** Expires every room past its deadline and returns how many were closed. */
  sweep(): number {
    let expired = 0;
    for (const [token, room] of this.rooms) {
      if (room.isExpired()) {
        room.expire();
        this.rooms.delete(token);
        expired += 1;
      }
    }
    return expired;
  }

  /** Closes every room, used on shutdown. */
  dispose(): void {
    for (const room of this.rooms.values()) {
      room.expire();
    }
    this.rooms.clear();
  }
}

/* -------------------------------------------------------------------------------------------- *
 * Cloudflare Workers adapter
 * -------------------------------------------------------------------------------------------- */

/**
 * Server-side WebSocket surface of the Workers runtime. Declared structurally so this package
 * compiles without pulling in `@cloudflare/workers-types`, and so Node type-checks never need it.
 */
interface EdgeWebSocket extends PeerSocket {
  accept(): void;
  addEventListener(type: "message", listener: (event: { data: unknown }) => void): void;
  addEventListener(type: "close", listener: () => void): void;
}

declare const WebSocketPair: new () => { readonly 0: EdgeWebSocket; readonly 1: EdgeWebSocket };

interface DurableObjectIdLike {
  readonly name?: string;
}

interface DurableObjectStubLike {
  fetch(request: Request): Promise<Response>;
}

interface DurableObjectNamespaceLike {
  idFromName(name: string): DurableObjectIdLike;
  get(id: DurableObjectIdLike): DurableObjectStubLike;
}

/** Bindings this worker expects. `SIGNALING_ROOMS` is a Durable Object namespace. */
export interface SignalingEnv {
  readonly SIGNALING_ROOMS: DurableObjectNamespaceLike;
}

function json(body: Record<string, unknown>, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

function statusFor(code: SignalingErrorCode): number {
  switch (code) {
    case "invalid-room":
    case "invalid-peer":
      return 400;
    case "room-full":
      return 409;
    case "duplicate-peer":
      return 409;
    case "payload-too-large":
      return 413;
    case "unknown-peer":
      return 404;
    case "room-expired":
      return 410;
  }
}

function errorResponse(error: unknown): Response {
  if (error instanceof SignalingError) {
    return json({ error: error.code, message: error.message }, statusFor(error.code));
  }
  return json({ error: "internal", message: "signaling relay failure" }, 500);
}

function upgradeRequested(request: Request): boolean {
  return (request.headers.get("upgrade") ?? "").toLowerCase() === "websocket";
}

/**
 * One Durable Object instance per room token. The instance holds the room's sockets in memory on
 * behalf of the relay; it never touches `state.storage`.
 */
export class SignalingDurableObject {
  private readonly relay = new SignalingRelay();
  private readonly sweeper: ReturnType<typeof setInterval>;

  constructor(_state: unknown, _env: unknown) {
    this.sweeper = setInterval(() => {
      this.relay.sweep();
    }, 15_000);
    // Timers must not keep the isolate alive on their own in Node-based tests.
    const handle = this.sweeper as unknown as { unref?: () => void };
    handle.unref?.();
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return json({ ok: true, rooms: this.relay.size }, 200);
    }
    if (!upgradeRequested(request)) {
      return json({ error: "upgrade-required", message: "connect with a WebSocket upgrade" }, 426);
    }

    const token = url.searchParams.get("room");
    const peerId = url.searchParams.get("peer");
    if (token === null || peerId === null) {
      return json({ error: "invalid-request", message: "room and peer query parameters are required" }, 400);
    }

    try {
      const pair = new WebSocketPair();
      const client = pair[0];
      const server = pair[1];
      server.accept();

      const room = this.relay.openRoom(token);
      room.join(peerId, server);

      server.addEventListener("message", (event) => {
        if (typeof event.data !== "string") {
          server.close(1003, "text frames only");
          return;
        }
        try {
          this.relay.relay(token, peerId, event.data);
        } catch (error) {
          server.close(error instanceof SignalingError ? 1008 : 1011, "relay rejected frame");
        }
      });
      server.addEventListener("close", () => {
        this.relay.leave(token, peerId);
      });

      return new Response(null, {
        status: 101,
        webSocket: client,
      } as ResponseInit & { webSocket: EdgeWebSocket });
    } catch (error) {
      return errorResponse(error);
    }
  }
}

/**
 * Worker entry point. Routes `/signal?room=<token>&peer=<id>` to the room's Durable Object;
 * `/health` reports liveness. No request body is stored, and no analytics or logs of payloads are
 * produced.
 */
const worker = {
  async fetch(request: Request, env: SignalingEnv): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return json({ ok: true }, 200);
    }
    if (url.pathname !== "/signal") {
      return json({ error: "not-found", message: "use /signal?room=<token>&peer=<id>" }, 404);
    }
    const token = url.searchParams.get("room");
    const peerId = url.searchParams.get("peer");
    if (token === null || peerId === null) {
      return json({ error: "invalid-request", message: "room and peer query parameters are required" }, 400);
    }
    if (!upgradeRequested(request)) {
      return json({ error: "upgrade-required", message: "connect with a WebSocket upgrade" }, 426);
    }
    try {
      const id = env.SIGNALING_ROOMS.idFromName(token);
      return env.SIGNALING_ROOMS.get(id).fetch(request);
    } catch (error) {
      return errorResponse(error);
    }
  },
};

export default worker;
