/**
 * WebRTC peer session: connection lifecycle, ECDH handshake, and encrypted data-channel messaging.
 *
 * The signaling transport is injected, so the same session code works over the bundled edge relay,
 * a WebSocket, or an in-process test harness. Signaling messages are treated as untrusted input:
 * every payload shape is validated before it reaches the peer connection, and the session key is
 * only derived from public keys carried in `hello` messages.
 */

import {
  decryptMessage,
  deriveSessionKeys,
  encryptMessage,
  exportPublicKey,
  generateEphemeralKeyPair,
  parseFrame,
  serializeFrame,
  type SessionKeys,
} from "./crypto.js";

/** Lifecycle states of a session. */
export type SessionState = "idle" | "handshaking" | "connecting" | "connected" | "closed" | "failed";

/** Signaling message types exchanged with the remote peer. */
export type SignalType = "hello" | "offer" | "answer" | "candidate" | "bye";

/** A signaling envelope. `payload` is validated per message type. */
export interface SignalMessage {
  readonly type: SignalType;
  readonly from: string;
  readonly payload?: unknown;
}

/** Transport contract for signaling, implemented by the caller's WebSocket client. */
export interface SignalingTransport {
  send(message: SignalMessage): void | Promise<void>;
  onMessage(handler: (message: SignalMessage) => void): void;
  close(): void;
}

export interface PeerSessionOptions {
  /** Local peer id, as registered with the signaling relay. */
  readonly peerId: string;
  /** Remote peer id; all other senders are ignored. */
  readonly remotePeerId: string;
  /** Whether this side creates the offer and data channel. */
  readonly initiator: boolean;
  /** Signaling channel to the remote peer. */
  readonly transport: SignalingTransport;
  /** Optional ICE servers; omit for host-candidate-only sessions. */
  readonly iceServers?: readonly RTCIceServer[];
  /** Injectable peer-connection factory, defaulting to the platform `RTCPeerConnection`. */
  readonly rtcFactory?: (configuration: RTCConfiguration) => RTCPeerConnection;
  /** Data channel label. Defaults to `secure-messages`. */
  readonly channelLabel?: string;
  /** Maximum messages queued while the data channel opens. */
  readonly maxQueuedMessages?: number;
  readonly onStateChange?: (state: SessionState) => void;
  readonly onMessage?: (text: string) => void;
  readonly onError?: (error: Error) => void;
}

const DEFAULT_CHANNEL_LABEL = "secure-messages";
const DEFAULT_MAX_QUEUE = 64;

const ALLOWED_TRANSITIONS: Readonly<Record<SessionState, readonly SessionState[]>> = {
  idle: ["handshaking"],
  handshaking: ["connecting", "failed", "closed"],
  connecting: ["connecting", "connected", "failed", "closed"],
  connected: ["failed", "closed"],
  failed: ["closed"],
  closed: [],
};

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function parseSessionDescription(value: unknown, expected: "offer" | "answer"): RTCSessionDescriptionInit {
  const record = requireRecord(value, `${expected} payload`);
  if (record["type"] !== expected) {
    throw new Error(`${expected} payload must have type "${expected}"`);
  }
  return { type: expected, sdp: requireString(record["sdp"], "sdp") };
}

function parseCandidate(value: unknown): RTCIceCandidateInit {
  const record = requireRecord(value, "candidate payload");
  const candidate = requireString(record["candidate"], "candidate");
  const init: RTCIceCandidateInit = { candidate };
  if (typeof record["sdpMid"] === "string") {
    init.sdpMid = record["sdpMid"];
  }
  if (typeof record["sdpMLineIndex"] === "number") {
    init.sdpMLineIndex = record["sdpMLineIndex"];
  }
  if (typeof record["usernameFragment"] === "string") {
    init.usernameFragment = record["usernameFragment"];
  }
  return init;
}

function parsePublicKeyJwk(value: unknown): JsonWebKey {
  const record = requireRecord(value, "hello key");
  if (record["kty"] !== "EC" || record["crv"] !== "P-256") {
    throw new Error("hello key must be an ECDH P-256 public key");
  }
  requireString(record["x"], "hello key x");
  requireString(record["y"], "hello key y");
  return record as JsonWebKey;
}

function toError(value: unknown): Error {
  return value instanceof Error ? value : new Error(String(value));
}

/**
 * A single peer-to-peer session.
 *
 * Call `start()` once, route signaling envelopes from the remote peer into `handleSignal`, and use
 * `send` once the state reaches `connected`. Messages sent earlier are queued, bounded by
 * `maxQueuedMessages`.
 */
export class PeerSession {
  readonly peerId: string;
  readonly remotePeerId: string;

  private readonly options: PeerSessionOptions;
  private readonly initiator: boolean;
  private readonly channelLabel: string;
  private readonly maxQueuedMessages: number;

  private stateValue: SessionState = "idle";
  private connection: RTCPeerConnection | undefined;
  private channel: RTCDataChannel | undefined;
  private keyPair: CryptoKeyPair | undefined;
  private sessionKeys: SessionKeys | undefined;
  private readonly outbox: string[] = [];
  private started = false;

  constructor(options: PeerSessionOptions) {
    if (options.peerId === options.remotePeerId) {
      throw new Error("peerId and remotePeerId must differ");
    }
    this.options = options;
    this.peerId = options.peerId;
    this.remotePeerId = options.remotePeerId;
    this.initiator = options.initiator;
    this.channelLabel = options.channelLabel ?? DEFAULT_CHANNEL_LABEL;
    this.maxQueuedMessages = options.maxQueuedMessages ?? DEFAULT_MAX_QUEUE;
    if (!Number.isInteger(this.maxQueuedMessages) || this.maxQueuedMessages < 0) {
      throw new RangeError("maxQueuedMessages must be a non-negative integer");
    }
  }

  /** Current lifecycle state. */
  get state(): SessionState {
    return this.stateValue;
  }

  /** Short verification code derived from both public keys, or `null` before the handshake. */
  get verificationCode(): string | null {
    if (this.sessionKeys === undefined) {
      return null;
    }
    const groups: string[] = [];
    for (let index = 0; index < 6; index += 1) {
      const byte = this.sessionKeys.transcript[index] ?? 0;
      groups.push(byte.toString(16).padStart(2, "0").toUpperCase());
    }
    return groups.join(" ");
  }

  /** Creates the peer connection, emits the local public key, and starts negotiation. */
  async start(): Promise<void> {
    if (this.started) {
      throw new Error("session has already been started");
    }
    this.started = true;
    this.transition("handshaking");

    const configuration: RTCConfiguration = this.options.iceServers === undefined
      ? {}
      : { iceServers: [...this.options.iceServers] };
    const connection = this.options.rtcFactory === undefined
      ? new RTCPeerConnection(configuration)
      : this.options.rtcFactory(configuration);
    this.connection = connection;

    connection.onicecandidate = (event) => {
      if (event.candidate !== null) {
        this.sendSignal({ type: "candidate", from: this.peerId, payload: event.candidate.toJSON() });
      }
    };
    connection.onconnectionstatechange = () => {
      if (connection.connectionState === "failed") {
        this.fail(new Error("peer connection failed"));
      }
    };
    connection.ondatachannel = (event) => {
      if (this.channel === undefined) {
        this.attachChannel(event.channel);
      }
    };

    if (this.initiator) {
      const channel = connection.createDataChannel(this.channelLabel, { ordered: true });
      this.attachChannel(channel);
    }

    this.options.transport.onMessage((message) => {
      void this.handleSignal(message);
    });

    this.keyPair = await generateEphemeralKeyPair();
    const publicKey = await exportPublicKey(this.keyPair.publicKey);
    this.sendSignal({ type: "hello", from: this.peerId, payload: { key: publicKey } });

    if (this.initiator) {
      await this.sendOffer();
    }
  }

  /** Routes a signaling envelope received from the transport. Unknown senders are ignored. */
  async handleSignal(message: SignalMessage): Promise<void> {
    if (message.from !== this.remotePeerId) {
      return;
    }
    if (this.stateValue === "closed") {
      return;
    }
    try {
      switch (message.type) {
        case "hello":
          await this.acceptHello(message.payload);
          break;
        case "offer":
          await this.acceptOffer(message.payload);
          break;
        case "answer":
          await this.acceptAnswer(message.payload);
          break;
        case "candidate":
          await this.acceptCandidate(message.payload);
          break;
        case "bye":
          this.close();
          break;
      }
    } catch (error) {
      this.fail(toError(error));
    }
  }

  /**
   * Encrypts and sends a UTF-8 message. Before the data channel opens the message is queued, up to
   * `maxQueuedMessages`; beyond that the promise rejects rather than growing without bound.
   */
  async send(plaintext: string): Promise<void> {
    if (this.stateValue === "closed" || this.stateValue === "failed") {
      throw new Error(`cannot send in state "${this.stateValue}"`);
    }
    if (typeof plaintext !== "string") {
      throw new TypeError("plaintext must be a string");
    }
    if (this.outbox.length >= this.maxQueuedMessages && (this.stateValue !== "connected" || !this.isChannelOpen())) {
      throw new Error(`outbox is full (${this.maxQueuedMessages} messages)`);
    }
    this.outbox.push(plaintext);
    await this.flushOutbox();
  }

  /** Closes the data channel, peer connection, and signaling transport. Idempotent. */
  close(): void {
    if (this.stateValue === "closed") {
      return;
    }
    this.channel?.close();
    this.connection?.close();
    this.options.transport.close();
    this.outbox.length = 0;
    this.transition("closed");
  }

  private async acceptHello(payload: unknown): Promise<void> {
    if (this.keyPair === undefined) {
      throw new Error("cannot accept hello before the session started");
    }
    const record = requireRecord(payload, "hello payload");
    const peerPublicKey = parsePublicKeyJwk(record["key"]);
    if (this.sessionKeys === undefined) {
      this.sessionKeys = await deriveSessionKeys(this.keyPair, peerPublicKey);
    }
  }

  private async sendOffer(): Promise<void> {
    const connection = this.requireConnection();
    const offer = await connection.createOffer();
    await connection.setLocalDescription(offer);
    this.sendSignal({ type: "offer", from: this.peerId, payload: connection.localDescription?.toJSON() ?? offer });
    this.transition("connecting");
  }

  private async acceptOffer(payload: unknown): Promise<void> {
    const connection = this.requireConnection();
    if (this.sessionKeys === undefined) {
      throw new Error("received an offer before the key exchange completed");
    }
    await connection.setRemoteDescription(parseSessionDescription(payload, "offer"));
    const answer = await connection.createAnswer();
    await connection.setLocalDescription(answer);
    this.sendSignal({ type: "answer", from: this.peerId, payload: connection.localDescription?.toJSON() ?? answer });
    this.transition("connecting");
  }

  private async acceptAnswer(payload: unknown): Promise<void> {
    const connection = this.requireConnection();
    await connection.setRemoteDescription(parseSessionDescription(payload, "answer"));
    this.transition("connecting");
  }

  private async acceptCandidate(payload: unknown): Promise<void> {
    const connection = this.requireConnection();
    await connection.addIceCandidate(parseCandidate(payload));
  }

  private attachChannel(channel: RTCDataChannel): void {
    this.channel = channel;
    channel.onopen = () => {
      this.transition("connected");
      void this.flushOutbox();
    };
    channel.onclose = () => {
      this.close();
    };
    channel.onerror = () => {
      this.fail(new Error("data channel error"));
    };
    channel.onmessage = (event: MessageEvent<unknown>) => {
      void this.handleEncryptedFrame(event.data);
    };
  }

  private async handleEncryptedFrame(data: unknown): Promise<void> {
    if (typeof data !== "string") {
      this.fail(new Error("received a non-text data channel frame"));
      return;
    }
    if (this.sessionKeys === undefined) {
      this.fail(new Error("received an encrypted frame before the key exchange completed"));
      return;
    }
    try {
      const frame = parseFrame(data);
      const plaintext = await decryptMessage(this.sessionKeys.key, frame);
      this.options.onMessage?.(plaintext);
    } catch (error) {
      this.fail(toError(error));
    }
  }

  private async flushOutbox(): Promise<void> {
    if (this.stateValue !== "connected" || !this.isChannelOpen() || this.sessionKeys === undefined) {
      return;
    }
    const channel = this.channel;
    if (channel === undefined) {
      return;
    }
    while (this.outbox.length > 0) {
      const message = this.outbox[0];
      if (message === undefined) {
        break;
      }
      const frame = await encryptMessage(this.sessionKeys.key, message);
      channel.send(serializeFrame(frame));
      this.outbox.shift();
    }
  }

  private isChannelOpen(): boolean {
    return this.channel?.readyState === "open";
  }

  private requireConnection(): RTCPeerConnection {
    if (this.connection === undefined) {
      throw new Error("session has not been started");
    }
    return this.connection;
  }

  private sendSignal(message: SignalMessage): void {
    try {
      const result = this.options.transport.send(message);
      if (result instanceof Promise) {
        result.catch((error: unknown) => this.fail(toError(error)));
      }
    } catch (error) {
      this.fail(toError(error));
    }
  }

  private transition(next: SessionState): void {
    if (next === this.stateValue) {
      return;
    }
    if (!ALLOWED_TRANSITIONS[this.stateValue].includes(next)) {
      throw new Error(`invalid session transition: ${this.stateValue} -> ${next}`);
    }
    this.stateValue = next;
    this.options.onStateChange?.(next);
  }

  private fail(error: Error): void {
    if (this.stateValue === "closed" || this.stateValue === "failed") {
      return;
    }
    this.channel?.close();
    this.connection?.close();
    this.options.onError?.(error);
    this.stateValue = "failed";
    this.options.onStateChange?.("failed");
  }
}
