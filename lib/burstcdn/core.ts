/**
 * Adaptive BurstCDN — Core Protocol, Bitfield, Verification, Circuit Breakers, and Scheduler
 * Implements Sections 5, 6, 7, 8, and Appendix A of the Adaptive BurstCDN Specification v1.0.
 */

export type AssetId = `sha256-${string}`;

export interface Manifest {
  v: 1;
  name: string;
  mime: string;
  size: number;
  chunkSize: number;
  chunkCount: number;
  hashAlg: 'sha256';
  hashes: string; // base64 of concatenated 32-byte chunk hashes
  urls: {
    cdn: string;
    origin: string;
  };
  p2p: boolean;
  version: string;
  sig: string | null;
}

export interface BurstConfig {
  chunkSize: number;
  fragmentSize: number;
  minP2PSize: number;
  slack: {
    normal: number;
    urgent: number;
    greedy: number;
  };
  cost: {
    peer: number;
    cdn: number;
    origin: number;
  };
  globalWindow: number;
  cdnWindow: number;
  targetPeers: number;
  maxPeers: number;
  iceTimeoutMs: number;
  ewmaAlpha: number;
  endgameThresholdRatio: number;
  originBreaker: {
    ttfbMs: number;
    errRate: number;
    ttfbWindow: number;
    errWindow: number;
  };
  swarmBreaker: {
    minSuccessRate: number;
    windowSize: number;
    maxHashFailsInWindow: number;
  };
  breakerCooldownMs: number;
  breakerMaxCooldownMs: number;
  uploadCapKbps: number;
  maxConcurrentUploads: number;
  banAfterHashFails: number;
  swTimeoutMs: number;
  reassemblyBufferMaxMiB: number;
  rejectRelay: boolean;
}

export const DEFAULT_BURST_CONFIG: BurstConfig = {
  chunkSize: 262144, // 256 KiB
  fragmentSize: 16384, // 16 KiB
  minP2PSize: 1048576, // 1 MiB
  slack: {
    normal: 1.5,
    urgent: 1.0,
    greedy: 3.0,
  },
  cost: {
    peer: 0,
    cdn: 1,
    origin: 3,
  },
  globalWindow: 16,
  cdnWindow: 4,
  targetPeers: 8,
  maxPeers: 15,
  iceTimeoutMs: 8000,
  ewmaAlpha: 0.3,
  endgameThresholdRatio: 0.02,
  originBreaker: {
    ttfbMs: 400,
    errRate: 0.2,
    ttfbWindow: 10,
    errWindow: 20,
  },
  swarmBreaker: {
    minSuccessRate: 0.6,
    windowSize: 30,
    maxHashFailsInWindow: 3,
  },
  breakerCooldownMs: 5000,
  breakerMaxCooldownMs: 60000,
  uploadCapKbps: 2000,
  maxConcurrentUploads: 4,
  banAfterHashFails: 2,
  swTimeoutMs: 250,
  reassemblyBufferMaxMiB: 64,
  rejectRelay: true,
};

// ----------------------------------------------------------------------------
// Deterministic & Real SHA-256 Hashing + Branded VerifiedBytes (Invariant I1)
// ----------------------------------------------------------------------------

declare const __verifiedBrand: unique symbol;
export type VerifiedBytes = Uint8Array & { readonly [__verifiedBrand]: true };

/**
 * Pure TypeScript / isomorphic SHA-256 implementation (FIPS 180-4)
 * Guarantees synchronous, deterministic SHA-256 verification in both Browser and Node.js
 * without async overhead during tight chunk verification loops.
 */
const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(n: number, x: number): number {
  return (x >>> n) | (x << (32 - n));
}

export function sha256Bytes(data: Uint8Array): Uint8Array {
  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  const bitLen = data.length * 8;
  const padLen = ((data.length + 9 + 63) & ~63);
  const padded = new Uint8Array(padLen);
  padded.set(data);
  padded[data.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000), false);
  view.setUint32(padLen - 4, bitLen >>> 0, false);

  const w = new Uint32Array(64);

  for (let offset = 0; offset < padLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(7, w[i - 15]) ^ rotr(18, w[i - 15]) ^ (w[i - 15] >>> 3);
      const s1 = rotr(17, w[i - 2]) ^ rotr(19, w[i - 2]) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let i = 0; i < 64; i++) {
      const S1 = rotr(6, e) ^ rotr(11, e) ^ rotr(25, e);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = rotr(2, a) ^ rotr(13, a) ^ rotr(22, a);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  outView.setUint32(0, h0, false);
  outView.setUint32(4, h1, false);
  outView.setUint32(8, h2, false);
  outView.setUint32(12, h3, false);
  outView.setUint32(16, h4, false);
  outView.setUint32(20, h5, false);
  outView.setUint32(24, h6, false);
  outView.setUint32(28, h7, false);
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

export function sha256Hex(data: Uint8Array | string): string {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  return bytesToHex(sha256Bytes(bytes));
}

export function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(b64, 'base64'));
  }
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

/**
 * Constant-time 32-byte digest comparison (Section 6.3.2)
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * ChunkVerifier: Only ChunkVerifier can produce VerifiedBytes (Invariant I1).
 */
export class ChunkVerifier {
  private readonly chunkHashes: Uint8Array;
  public readonly chunkCount: number;

  constructor(manifest: Manifest) {
    this.chunkHashes = base64ToBytes(manifest.hashes);
    this.chunkCount = manifest.chunkCount;
    if (this.chunkHashes.length !== this.chunkCount * 32) {
      throw new Error(
        `Invalid manifest hashes length: expected ${this.chunkCount * 32}, got ${this.chunkHashes.length}`
      );
    }
  }

  public getExpectedHash(chunkIndex: number): Uint8Array {
    if (chunkIndex < 0 || chunkIndex >= this.chunkCount) {
      throw new RangeError(`Chunk index ${chunkIndex} out of bounds [0, ${this.chunkCount})`);
    }
    return this.chunkHashes.subarray(chunkIndex * 32, (chunkIndex + 1) * 32);
  }

  public getExpectedHashHex(chunkIndex: number): string {
    return bytesToHex(this.getExpectedHash(chunkIndex));
  }

  public verifyChunk(chunkIndex: number, rawBytes: Uint8Array): VerifiedBytes | null {
    const actual = sha256Bytes(rawBytes);
    const expected = this.getExpectedHash(chunkIndex);
    if (!constantTimeEqual(actual, expected)) {
      return null;
    }
    return rawBytes as VerifiedBytes;
  }
}

/**
 * ManifestVerifier (Section 6.3.1): Self-certifying manifest validation
 */
export function verifyManifestBytes(
  manifestJsonBytes: Uint8Array | string,
  requestedAssetId: AssetId
): { ok: true; manifest: Manifest } | { ok: false; error: string } {
  const rawBytes =
    typeof manifestJsonBytes === 'string'
      ? new TextEncoder().encode(manifestJsonBytes)
      : manifestJsonBytes;
  const computedId: AssetId = `sha256-${sha256Hex(rawBytes)}`;
  if (computedId !== requestedAssetId) {
    return {
      ok: false,
      error: `Self-certifying hash mismatch: expected ${requestedAssetId}, got ${computedId}`,
    };
  }
  try {
    const parsed = JSON.parse(new TextDecoder().decode(rawBytes)) as Manifest;
    if (parsed.v !== 1 || parsed.hashAlg !== 'sha256') {
      return { ok: false, error: 'Unsupported manifest schema version or hashAlg' };
    }
    const expectedChunks = Math.ceil(parsed.size / parsed.chunkSize);
    if (parsed.chunkCount !== expectedChunks) {
      return {
        ok: false,
        error: `chunkCount mismatch: expected ${expectedChunks}, got ${parsed.chunkCount}`,
      };
    }
    const hashBytes = base64ToBytes(parsed.hashes);
    if (hashBytes.length !== parsed.chunkCount * 32) {
      return {
        ok: false,
        error: `Concatenated hash byte length (${hashBytes.length}) !== 32 * chunkCount (${parsed.chunkCount * 32})`,
      };
    }
    return { ok: true, manifest: parsed };
  } catch (err) {
    return { ok: false, error: `Invalid JSON: ${(err as Error).message}` };
  }
}

// ----------------------------------------------------------------------------
// Binary Wire Protocol Codec (Section 5.3)
// 15-byte Big-Endian Header:
//   0: type (u8)
//   1..2: swarm (u16)
//   3..6: chunk (u32)
//   7..10: offset (u32)
//   11..14: total (u32)
//   15..: payload (Uint8Array)
// ----------------------------------------------------------------------------

export const WireFrameType = {
  HELLO: 0x01,
  BITFIELD: 0x02,
  HAVE: 0x03,
  REQUEST: 0x04,
  CHUNK_FRAG: 0x05,
  CANCEL: 0x06,
  REJECT: 0x07,
  PING: 0x08,
  PONG: 0x09,
  BYE: 0x0a,
} as const;
export type WireFrameType = (typeof WireFrameType)[keyof typeof WireFrameType];

export const RejectReasonCode = {
  NOT_HAVE: 1,
  BUSY: 2,
  RATE_LIMITED: 3,
} as const;
export type RejectReasonCode = (typeof RejectReasonCode)[keyof typeof RejectReasonCode];

export interface WireFrame {
  type: WireFrameType;
  swarm: number; // u16
  chunk: number; // u32
  offset: number; // u32
  total: number; // u32
  payload: Uint8Array;
}

export const WIRE_HEADER_BYTES = 15;

export function encodeWireFrame(frame: WireFrame): Uint8Array {
  const buf = new Uint8Array(WIRE_HEADER_BYTES + frame.payload.length);
  const view = new DataView(buf.buffer);
  view.setUint8(0, frame.type);
  view.setUint16(1, frame.swarm & 0xffff, false);
  view.setUint32(3, frame.chunk >>> 0, false);
  view.setUint32(7, frame.offset >>> 0, false);
  view.setUint32(11, frame.total >>> 0, false);
  buf.set(frame.payload, WIRE_HEADER_BYTES);
  return buf;
}

export function decodeWireFrame(raw: Uint8Array): WireFrame {
  if (raw.length < WIRE_HEADER_BYTES) {
    throw new RangeError(`Wire frame too short: ${raw.length} < ${WIRE_HEADER_BYTES} bytes`);
  }
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  const type = view.getUint8(0) as WireFrameType;
  if (type < WireFrameType.HELLO || type > WireFrameType.BYE) {
    throw new Error(`Unknown WireFrameType: 0x${type.toString(16)}`);
  }
  const swarm = view.getUint16(1, false);
  const chunk = view.getUint32(3, false);
  const offset = view.getUint32(7, false);
  const total = view.getUint32(11, false);
  const payload = raw.slice(WIRE_HEADER_BYTES);
  return { type, swarm, chunk, offset, total, payload };
}

/**
 * Fragment a verified chunk into <= min(16 KiB, sctp.maxMessageSize) CHUNK_FRAG frames (Constraint C3)
 */
export function fragmentChunkToFrames(
  swarm: number,
  chunkIndex: number,
  chunkBytes: Uint8Array,
  maxMessageSize = 16384
): WireFrame[] {
  const maxPayload = Math.max(1024, Math.min(16384, maxMessageSize) - WIRE_HEADER_BYTES);
  const frames: WireFrame[] = [];
  const total = chunkBytes.length;

  for (let offset = 0; offset < total; offset += maxPayload) {
    const slice = chunkBytes.subarray(offset, Math.min(offset + maxPayload, total));
    frames.push({
      type: WireFrameType.CHUNK_FRAG,
      swarm,
      chunk: chunkIndex,
      offset,
      total,
      payload: new Uint8Array(slice),
    });
  }
  return frames;
}

/**
 * ReassemblyBuffer: Reassembles CHUNK_FRAG frames and enforces global memory cap (Section 7.4)
 */
export class ChunkReassembler {
  private readonly buffers = new Map<
    string,
    { total: number; receivedBytes: number; seenOffsets: Set<number>; data: Uint8Array }
  >();
  private currentBufferedBytes = 0;
  private readonly maxBufferBytes: number;

  constructor(maxMiB = 64) {
    this.maxBufferBytes = maxMiB * 1024 * 1024;
  }

  public get bufferedBytes(): number {
    return this.currentBufferedBytes;
  }

  public pushFragment(frame: WireFrame): Uint8Array | null {
    if (frame.type !== WireFrameType.CHUNK_FRAG) {
      throw new Error('Expected CHUNK_FRAG frame');
    }
    if (frame.offset + frame.payload.length > frame.total || frame.total === 0) {
      throw new RangeError('Invalid fragment offset/length bounds');
    }

    const key = `${frame.swarm}:${frame.chunk}`;
    let entry = this.buffers.get(key);
    if (!entry) {
      if (this.currentBufferedBytes + frame.total > this.maxBufferBytes) {
        throw new Error(`Reassembly memory cap exceeded (${this.maxBufferBytes} bytes)`);
      }
      entry = {
        total: frame.total,
        receivedBytes: 0,
        seenOffsets: new Set<number>(),
        data: new Uint8Array(frame.total),
      };
      this.buffers.set(key, entry);
      this.currentBufferedBytes += frame.total;
    }

    if (entry.total !== frame.total) {
      this.discard(frame.swarm, frame.chunk);
      throw new Error('Inconsistent total chunk size across fragments');
    }

    // Ignore duplicate fragment at identical offset
    if (!entry.seenOffsets.has(frame.offset)) {
      entry.seenOffsets.add(frame.offset);
      entry.data.set(frame.payload, frame.offset);
      entry.receivedBytes += frame.payload.length;
    }

    if (entry.receivedBytes === entry.total) {
      this.buffers.delete(key);
      this.currentBufferedBytes -= entry.total;
      return entry.data;
    }
    return null;
  }

  public discard(swarm: number, chunk: number): void {
    const key = `${swarm}:${chunk}`;
    const entry = this.buffers.get(key);
    if (entry) {
      this.currentBufferedBytes -= entry.total;
      this.buffers.delete(key);
    }
  }

  public clear(): void {
    this.buffers.clear();
    this.currentBufferedBytes = 0;
  }
}

/**
 * Glare avoidance (Section 5.3): lexicographically smaller peerId initiates WebRTC offer.
 */
export function shouldInitiateOffer(localPeerId: string, remotePeerId: string): boolean {
  if (localPeerId === remotePeerId) {
    throw new Error('Cannot connect peer to itself');
  }
  return localPeerId < remotePeerId;
}

// ----------------------------------------------------------------------------
// Bitfield (Section 6.3.3) — Bit-packed Uint8Array
// ----------------------------------------------------------------------------

export class Bitfield {
  public readonly length: number;
  private readonly bytes: Uint8Array;
  private setCount = 0;

  constructor(chunkCount: number, initialBytes?: Uint8Array) {
    this.length = chunkCount;
    const byteLength = Math.ceil(chunkCount / 8);
    this.bytes = new Uint8Array(byteLength);
    if (initialBytes) {
      this.bytes.set(initialBytes.subarray(0, byteLength));
      // Clear any trailing unused bits in last byte
      const rem = chunkCount % 8;
      if (rem !== 0 && byteLength > 0) {
        const mask = (0xff << (8 - rem)) & 0xff;
        this.bytes[byteLength - 1] &= mask;
      }
      let c = 0;
      for (let i = 0; i < chunkCount; i++) {
        if (this.has(i)) c++;
      }
      this.setCount = c;
    }
  }

  public has(index: number): boolean {
    if (index < 0 || index >= this.length) return false;
    const byteIndex = index >> 3;
    const bitMask = 1 << (7 - (index & 7));
    return (this.bytes[byteIndex] & bitMask) !== 0;
  }

  public set(index: number): boolean {
    if (index < 0 || index >= this.length) {
      throw new RangeError(`Bitfield index ${index} out of range [0, ${this.length})`);
    }
    const byteIndex = index >> 3;
    const bitMask = 1 << (7 - (index & 7));
    if ((this.bytes[byteIndex] & bitMask) === 0) {
      this.bytes[byteIndex] |= bitMask;
      this.setCount++;
      return true;
    }
    return false;
  }

  public clear(index: number): boolean {
    if (index < 0 || index >= this.length) return false;
    const byteIndex = index >> 3;
    const bitMask = 1 << (7 - (index & 7));
    if ((this.bytes[byteIndex] & bitMask) !== 0) {
      this.bytes[byteIndex] &= ~bitMask;
      this.setCount--;
      return true;
    }
    return false;
  }

  public count(): number {
    return this.setCount;
  }

  public progress(): number {
    return this.length === 0 ? 1 : this.setCount / this.length;
  }

  public isComplete(): boolean {
    return this.setCount === this.length;
  }

  public iterateMissing(): number[] {
    const missing: number[] = [];
    for (let i = 0; i < this.length; i++) {
      if (!this.has(i)) missing.push(i);
    }
    return missing;
  }

  /**
   * Returns chunks that THIS bitfield is missing AND `other` peer HAS.
   */
  public intersectionMissing(otherHas: Bitfield): number[] {
    const result: number[] = [];
    const max = Math.min(this.length, otherHas.length);
    for (let i = 0; i < max; i++) {
      if (!this.has(i) && otherHas.has(i)) {
        result.push(i);
      }
    }
    return result;
  }

  public toBytes(): Uint8Array {
    return new Uint8Array(this.bytes);
  }

  public static fromBytes(chunkCount: number, raw: Uint8Array): Bitfield {
    return new Bitfield(chunkCount, raw);
  }
}

// ----------------------------------------------------------------------------
// Circuit Breakers (Section 6.3.6): Origin & Swarm State Machines
// CLOSED -> OPEN -> HALF_OPEN -> CLOSED
// ----------------------------------------------------------------------------

export type BreakerState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export class OriginCircuitBreaker {
  private state: BreakerState = 'CLOSED';
  private ttfbEwma = 85;
  private sampleCount = 0;
  private recentOutcomes: boolean[] = []; // true = error (429/503/timeout), false = ok
  private openedAtMs = 0;
  private currentCooldownMs: number;
  private halfOpenSuccesses = 0;
  private readonly requiredProbes = 2;
  private readonly config: BurstConfig;

  constructor(config: BurstConfig = DEFAULT_BURST_CONFIG) {
    this.config = config;
    this.currentCooldownMs = config.breakerCooldownMs;
  }

  public getState(nowMs: number): BreakerState {
    if (this.state === 'OPEN' && nowMs - this.openedAtMs >= this.currentCooldownMs) {
      this.state = 'HALF_OPEN';
      this.halfOpenSuccesses = 0;
    }
    return this.state;
  }

  public getTtfbEwma(): number {
    return this.ttfbEwma;
  }

  public getErrorRate(): number {
    if (this.recentOutcomes.length === 0) return 0;
    const errs = this.recentOutcomes.filter(Boolean).length;
    return errs / this.recentOutcomes.length;
  }

  public recordSample(ttfbMs: number, isError: boolean, nowMs: number): BreakerState {
    this.getState(nowMs);

    if (this.state === 'HALF_OPEN') {
      if (isError || ttfbMs > this.config.originBreaker.ttfbMs) {
        this.state = 'OPEN';
        this.openedAtMs = nowMs;
        this.currentCooldownMs = Math.min(
          this.config.breakerMaxCooldownMs,
          this.currentCooldownMs * 2
        );
        return this.state;
      } else {
        this.halfOpenSuccesses++;
        if (this.halfOpenSuccesses >= this.requiredProbes) {
          this.state = 'CLOSED';
          this.currentCooldownMs = this.config.breakerCooldownMs;
          this.recentOutcomes = [];
          this.ttfbEwma = ttfbMs;
        }
        return this.state;
      }
    }

    this.sampleCount++;
    const alpha = this.config.ewmaAlpha;
    this.ttfbEwma =
      this.sampleCount === 1 ? ttfbMs : alpha * ttfbMs + (1 - alpha) * this.ttfbEwma;

    this.recentOutcomes.push(isError);
    if (this.recentOutcomes.length > this.config.originBreaker.errWindow) {
      this.recentOutcomes.shift();
    }

    const highTtfb =
      this.sampleCount >= this.config.originBreaker.ttfbWindow &&
      this.ttfbEwma > this.config.originBreaker.ttfbMs;
    const highErrRate =
      this.recentOutcomes.length >= 5 &&
      this.getErrorRate() > this.config.originBreaker.errRate;

    if (this.state === 'CLOSED' && (highTtfb || highErrRate)) {
      this.state = 'OPEN';
      this.openedAtMs = nowMs;
    }

    return this.state;
  }

  public forceTrip(nowMs: number): void {
    this.state = 'OPEN';
    this.openedAtMs = nowMs;
    this.ttfbEwma = 620;
  }

  public reset(): void {
    this.state = 'CLOSED';
    this.ttfbEwma = 85;
    this.sampleCount = 0;
    this.recentOutcomes = [];
    this.currentCooldownMs = this.config.breakerCooldownMs;
  }
}

export class SwarmCircuitBreaker {
  private state: BreakerState = 'CLOSED';
  private recentOutcomes: boolean[] = []; // true = success, false = fail
  private recentHashFailTimestamps: number[] = [];
  private openedAtMs = 0;
  private currentCooldownMs: number;
  private halfOpenSuccesses = 0;
  private readonly config: BurstConfig;

  constructor(config: BurstConfig = DEFAULT_BURST_CONFIG) {
    this.config = config;
    this.currentCooldownMs = config.breakerCooldownMs;
  }

  public getState(nowMs: number): BreakerState {
    if (this.state === 'OPEN' && nowMs - this.openedAtMs >= this.currentCooldownMs) {
      this.state = 'HALF_OPEN';
      this.halfOpenSuccesses = 0;
    }
    return this.state;
  }

  public getSuccessRate(): number {
    if (this.recentOutcomes.length === 0) return 1;
    const okCount = this.recentOutcomes.filter(Boolean).length;
    return okCount / this.recentOutcomes.length;
  }

  public recordPeerOutcome(ok: boolean, hashFailed: boolean, nowMs: number): BreakerState {
    this.getState(nowMs);

    if (hashFailed) {
      this.recentHashFailTimestamps.push(nowMs);
    }
    this.recentHashFailTimestamps = this.recentHashFailTimestamps.filter(
      (ts) => nowMs - ts <= 30000
    );

    if (this.state === 'HALF_OPEN') {
      if (!ok || hashFailed) {
        this.state = 'OPEN';
        this.openedAtMs = nowMs;
        this.currentCooldownMs = Math.min(
          this.config.breakerMaxCooldownMs,
          this.currentCooldownMs * 2
        );
        return this.state;
      }
      this.halfOpenSuccesses++;
      if (this.halfOpenSuccesses >= 2) {
        this.state = 'CLOSED';
        this.currentCooldownMs = this.config.breakerCooldownMs;
        this.recentOutcomes = [];
      }
      return this.state;
    }

    this.recentOutcomes.push(ok && !hashFailed);
    if (this.recentOutcomes.length > this.config.swarmBreaker.windowSize) {
      this.recentOutcomes.shift();
    }

    const lowSuccess =
      this.recentOutcomes.length >= 10 &&
      this.getSuccessRate() < this.config.swarmBreaker.minSuccessRate;
    const tooManyHashFails =
      this.recentHashFailTimestamps.length >= this.config.swarmBreaker.maxHashFailsInWindow;

    if (this.state === 'CLOSED' && (lowSuccess || tooManyHashFails)) {
      this.state = 'OPEN';
      this.openedAtMs = nowMs;
    }

    return this.state;
  }

  public reset(): void {
    this.state = 'CLOSED';
    this.recentOutcomes = [];
    this.recentHashFailTimestamps = [];
    this.currentCooldownMs = this.config.breakerCooldownMs;
  }
}

// ----------------------------------------------------------------------------
// Peer Scoring, BDP Windowing, and Per-Chunk Source Selection (Section 7)
// ----------------------------------------------------------------------------

export type SourceKind = 'peer' | 'cdn' | 'origin';
export type SlackMode = 'urgent' | 'normal' | 'greedy';

export interface PeerStat {
  peerId: string;
  region: string;
  viaRelay: boolean; // TURN relay flag (C4 / ADR-006)
  rttEwmaMs: number;
  tputEwmaBps: number; // Bytes per second
  inflight: number;
  window: number;
  successStreak: number;
  totalSuccesses: number;
  timeouts: number;
  hashFails: number;
  bytesDown: number;
  bytesUp: number;
  banned: boolean;
  rejectedRelay: boolean;
  bitfield: Bitfield;
}

/**
 * Compute BDP (Bandwidth-Delay Product) in-flight chunk window (Section 6.3.5):
 * Wp = clamp(ceil(tputEwma * rttEwma / chunkSize) + 1, 1, 8)
 */
export function computeBdpWindow(
  tputBytesPerSec: number,
  rttMs: number,
  chunkSize: number
): number {
  const bdpBytes = tputBytesPerSec * (rttMs / 1000);
  const raw = Math.ceil(bdpBytes / chunkSize) + 1;
  return Math.max(1, Math.min(8, raw));
}

/**
 * Peer Score (Section 7.3):
 * score(p) = tputEwma(p) / (1 + 3 * timeouts(p) + 10 * hashFails(p))
 */
export function computePeerScore(peer: Pick<PeerStat, 'tputEwmaBps' | 'timeouts' | 'hashFails'>): number {
  return peer.tputEwmaBps / (1 + 3 * peer.timeouts + 10 * peer.hashFails);
}

export interface CandidateEvaluation {
  kind: SourceKind;
  id: string;
  etaMs: number;
  cost: number;
  withinSlack: boolean;
  selected: boolean;
  reason?: string;
}

export interface SourceDecision {
  chunkIndex: number;
  chosen: CandidateEvaluation;
  fastestEtaMs: number;
  slackMultiplier: number;
  allCandidates: CandidateEvaluation[];
  endgameDuplicate?: CandidateEvaluation;
}

/**
 * Adaptive Scheduler (Section 7.1, 7.2, 7.3, 7.4)
 */
export class BurstScheduler {
  public readonly originBreaker: OriginCircuitBreaker;
  public readonly swarmBreaker: SwarmCircuitBreaker;
  public readonly config: BurstConfig;
  public relayRejectedCount = 0;
  public hedgesIssued = 0;
  public totalRequestsIssued = 0;

  constructor(config: BurstConfig = DEFAULT_BURST_CONFIG) {
    this.config = config;
    this.originBreaker = new OriginCircuitBreaker(config);
    this.swarmBreaker = new SwarmCircuitBreaker(config);
  }

  /**
   * Registers or evaluates a peer connection; enforces ADR-006 TURN relay rejection.
   */
  public evaluatePeerAdmission(peer: PeerStat): { admitted: boolean; reason?: string } {
    if (peer.banned || peer.hashFails >= this.config.banAfterHashFails) {
      peer.banned = true;
      return { admitted: false, reason: 'BANNED_HASH_FAIL' };
    }
    if (this.config.rejectRelay && peer.viaRelay) {
      if (!peer.rejectedRelay) {
        peer.rejectedRelay = true;
        this.relayRejectedCount++;
      }
      return { admitted: false, reason: 'RELAYED_TURN_REJECTED' };
    }
    return { admitted: true };
  }

  /**
   * Updates peer statistics on chunk completion or failure (EWMA + AIMD + Banning)
   */
  public recordPeerTransfer(
    peer: PeerStat,
    opts: {
      ok: boolean;
      hashOk: boolean;
      bytes: number;
      rttMs: number;
      durMs: number;
      chunkSize: number;
      nowMs: number;
    }
  ): void {
    const alpha = this.config.ewmaAlpha;
    if (!opts.hashOk) {
      peer.hashFails++;
      if (peer.hashFails >= this.config.banAfterHashFails) {
        peer.banned = true;
      }
      this.swarmBreaker.recordPeerOutcome(false, true, opts.nowMs);
      return;
    }

    if (!opts.ok) {
      peer.timeouts++;
      peer.successStreak = 0;
      // AIMD multiplicative decrease on timeout (Section 7.4)
      peer.window = Math.max(1, Math.floor(peer.window * 0.5));
      this.swarmBreaker.recordPeerOutcome(false, false, opts.nowMs);
      return;
    }

    // Valid verified transfer
    const sampleTput = opts.durMs > 0 ? (opts.bytes * 1000) / opts.durMs : peer.tputEwmaBps;
    peer.rttEwmaMs = alpha * opts.rttMs + (1 - alpha) * peer.rttEwmaMs;
    peer.tputEwmaBps = alpha * sampleTput + (1 - alpha) * peer.tputEwmaBps;
    peer.bytesDown += opts.bytes;
    peer.totalSuccesses++;
    peer.successStreak++;

    // Probation promotion & AIMD window sizing
    const bdpTarget = computeBdpWindow(peer.tputEwmaBps, peer.rttEwmaMs, opts.chunkSize);
    if (peer.totalSuccesses <= 3) {
      peer.window = peer.totalSuccesses < 3 ? 1 : bdpTarget;
    } else if (peer.successStreak >= peer.window) {
      peer.window = Math.min(8, Math.max(bdpTarget, peer.window + 1));
      peer.successStreak = 0;
    }

    this.swarmBreaker.recordPeerOutcome(true, false, opts.nowMs);
  }

  /**
   * Core per-chunk source decision (Section 7.1):
   *   eta(s) = queueWait(s) + rtt(s) + b / tput(s)
   *   Rule: choose the cheapest source whose eta is within `slack * bestEta`
   */
  public chooseSourceForChunk(params: {
    manifest: Manifest;
    chunkIndex: number;
    chunkByteSize: number;
    peers: PeerStat[];
    cdnStat: { rttMs: number; tputBps: number; inflight: number; healthy: boolean };
    originStat: { rttMs: number; tputBps: number; inflight: number };
    slackMode: SlackMode;
    isColdStartChunk?: boolean;
    remainingChunksCount?: number;
    nowMs: number;
  }): SourceDecision {
    const {
      manifest,
      chunkIndex,
      chunkByteSize,
      peers,
      cdnStat,
      originStat,
      slackMode,
      isColdStartChunk = false,
      remainingChunksCount = manifest.chunkCount,
      nowMs,
    } = params;

    const slackMultiplier = this.config.slack[slackMode];
    const originState = this.originBreaker.getState(nowMs);
    const swarmState = this.swarmBreaker.getState(nowMs);

    // Policy check: small assets (< minP2PSize) or p2p:false always use CDN (Section 4.4)
    const p2pEligible =
      manifest.p2p &&
      manifest.size >= this.config.minP2PSize &&
      !isColdStartChunk &&
      swarmState !== 'OPEN';

    const candidates: CandidateEvaluation[] = [];

    // 1. Evaluate eligible Peers having chunkIndex
    if (p2pEligible) {
      for (const peer of peers) {
        const admission = this.evaluatePeerAdmission(peer);
        if (!admission.admitted) continue;
        if (!peer.bitfield.has(chunkIndex)) continue;

        const queueChunks = Math.max(0, peer.inflight - peer.window + 1);
        const singleTransferMs = (chunkByteSize / Math.max(1024, peer.tputEwmaBps)) * 1000;
        const queueWaitMs = queueChunks * singleTransferMs;
        // Apply slight score penalty to ETA for unreliable peers
        const reliabilityPenalty = 1 + 0.5 * peer.timeouts + 2 * peer.hashFails;
        const etaMs = (queueWaitMs + peer.rttEwmaMs + singleTransferMs) * reliabilityPenalty;

        candidates.push({
          kind: 'peer',
          id: peer.peerId,
          etaMs,
          cost: this.config.cost.peer,
          withinSlack: false,
          selected: false,
        });
      }
    }

    // 2. Evaluate CDN Edge
    if (cdnStat.healthy) {
      const cdnQueue = Math.max(0, cdnStat.inflight - this.config.cdnWindow + 1);
      const cdnTransferMs = (chunkByteSize / Math.max(1024, cdnStat.tputBps)) * 1000;
      const cdnEtaMs = cdnQueue * cdnTransferMs + cdnStat.rttMs + cdnTransferMs;
      // When Origin Breaker is OPEN, CDN cost rises to encourage swarm-first (Section 7.1)
      const cdnCost =
        originState === 'OPEN' ? this.config.cost.cdn + 1.5 : this.config.cost.cdn;

      candidates.push({
        kind: 'cdn',
        id: 'cdn-edge',
        etaMs: cdnEtaMs,
        cost: cdnCost,
        withinSlack: false,
        selected: false,
      });
    }

    // 3. Evaluate Origin fallback (only if CDN unhealthy or no other candidates or breaker CLOSED)
    const includeOrigin =
      !cdnStat.healthy || candidates.length === 0 || originState !== 'OPEN';
    if (includeOrigin) {
      const origTransferMs = (chunkByteSize / Math.max(1024, originStat.tputBps)) * 1000;
      const origEtaMs =
        originStat.inflight * origTransferMs + originStat.rttMs + origTransferMs;
      const origCost =
        originState === 'OPEN' ? Number.POSITIVE_INFINITY : this.config.cost.origin;

      candidates.push({
        kind: 'origin',
        id: 'origin-primary',
        etaMs: origEtaMs,
        cost: origCost,
        withinSlack: false,
        selected: false,
      });
    }

    const bestEtaMs = Math.min(...candidates.map((c) => c.etaMs));
    const maxAllowedEta = bestEtaMs * slackMultiplier;

    for (const c of candidates) {
      c.withinSlack = c.etaMs <= maxAllowedEta && Number.isFinite(c.cost);
    }

    // Filter to candidates within slack; if none (e.g. only origin with Infinity cost), fall back to lowest ETA (Fail-open G4)
    const eligible = candidates.filter((c) => c.withinSlack);
    const pool = eligible.length > 0 ? eligible : candidates;

    pool.sort((a, b) => {
      if (a.cost !== b.cost) return a.cost - b.cost;
      return a.etaMs - b.etaMs;
    });

    const chosen = pool[0];
    chosen.selected = true;

    // Endgame mode check (Section 7.2): when remaining <= min(4, 2% of total), pick secondary source
    const endgameLimit = Math.max(1, Math.min(4, Math.ceil(manifest.chunkCount * this.config.endgameThresholdRatio)));
    let endgameDuplicate: CandidateEvaluation | undefined;
    if (remainingChunksCount <= endgameLimit && candidates.length > 1) {
      const runnerUp = candidates
        .filter((c) => c.id !== chosen.id)
        .sort((a, b) => a.etaMs - b.etaMs)[0];
      if (runnerUp) {
        endgameDuplicate = runnerUp;
      }
    }

    this.totalRequestsIssued++;

    return {
      chunkIndex,
      chosen,
      fastestEtaMs: bestEtaMs,
      slackMultiplier,
      allCandidates: candidates,
      endgameDuplicate,
    };
  }

  /**
   * Chunk ordering (Section 7.2):
   * - bulk: random-first for first K=4 chunks, then rarest-first for peer lanes
   *   and zero/low-availability seeding for CDN lane.
   * - sequential: in-order lookahead window L from playhead.
   */
  public orderMissingChunks(params: {
    localBitfield: Bitfield;
    peers: PeerStat[];
    mode: 'bulk' | 'sequential' | 'range';
    completedChunksCount: number;
    preferRareZeroForCdn?: boolean;
    seed?: number;
  }): number[] {
    const missing = params.localBitfield.iterateMissing();
    if (missing.length <= 1) return missing;

    if (params.mode === 'sequential' || params.mode === 'range') {
      return missing; // Already sorted ascending
    }

    const activePeers = params.peers.filter((p) => !p.banned && !p.rejectedRelay);

    // Availability map: how many connected peers have chunk i
    const availability = new Map<number, number>();
    for (const idx of missing) {
      let count = 0;
      for (const p of activePeers) {
        if (p.bitfield.has(idx)) count++;
      }
      availability.set(idx, count);
    }

    // Seeded deterministic tie-breaker
    let rngState = (params.seed ?? 1337) + params.completedChunksCount * 7919;
    const nextRand = () => {
      rngState = (rngState * 1664525 + 1013904223) >>> 0;
      return rngState / 0x100000000;
    };

    // Random-first for the first K=4 chunks to bootstrap swarm diversity
    if (params.completedChunksCount < 4 && !params.preferRareZeroForCdn) {
      const shuffled = [...missing];
      for (let i = shuffled.length - 1; i > 0; i--) {
        const j = Math.floor(nextRand() * (i + 1));
        const tmp = shuffled[i];
        shuffled[i] = shuffled[j];
        shuffled[j] = tmp;
      }
      return shuffled;
    }

    // Lane specialization (Section 7.2):
    // CDN lane prefers chunks with 0 or lowest peer availability ("seeds the rare pieces").
    // Peer lane prefers rarest-first among chunks that at least 1 peer has (`avail > 0`).
    return [...missing].sort((a, b) => {
      const avA = availability.get(a) ?? 0;
      const avB = availability.get(b) ?? 0;

      if (!params.preferRareZeroForCdn) {
        const hasA = avA > 0 ? 1 : 0;
        const hasB = avB > 0 ? 1 : 0;
        if (hasA !== hasB) return hasB - hasA; // Peers first pick chunks available in swarm
      }

      if (avA !== avB) return avA - avB; // Rarest first
      return a - b;
    });
  }

  /**
   * Hedged request decision (Section 7.2):
   * hedgeAfter = max(1.5 * P95, 2 * rtt), capped at <= 5% of total requests
   */
  public shouldIssueHedge(params: {
    elapsedMs: number;
    sourceRttMs: number;
    sourceP95LatencyMs: number;
  }): { hedge: boolean; thresholdMs: number } {
    const thresholdMs = Math.max(1.5 * params.sourceP95LatencyMs, 2 * params.sourceRttMs);
    const currentHedgeRatio =
      this.totalRequestsIssued > 0 ? this.hedgesIssued / this.totalRequestsIssued : 0;
    if (params.elapsedMs >= thresholdMs && currentHedgeRatio < 0.05) {
      this.hedgesIssued++;
      return { hedge: true, thresholdMs };
    }
    return { hedge: false, thresholdMs };
  }
}

// ----------------------------------------------------------------------------
// Deterministic Demo Asset Catalog & Self-Certifying Manifest Builder
// ----------------------------------------------------------------------------

export interface CatalogAsset {
  key: string;
  assetId: AssetId;
  manifest: Manifest;
  manifestRawJson: string;
  description: string;
  category: 'ML Weights' | 'WASM Bundle' | '4K Media' | 'Small Static';
  recommendedMode: 'bulk' | 'sequential';
}

/**
 * Generates deterministic synthetic chunk bytes for a given asset key and chunk index
 * so that real SHA-256 verification works end-to-end across Origin API, Peers, and Browser Agent.
 */
export function generateDeterministicChunkBytes(
  assetKey: string,
  chunkIndex: number,
  byteLength = 4096
): Uint8Array {
  const out = new Uint8Array(byteLength);
  let seed = 2166136261;
  const tag = `${assetKey}:chunk:${chunkIndex}`;
  for (let i = 0; i < tag.length; i++) {
    seed ^= tag.charCodeAt(i);
    seed = Math.imul(seed, 16777619) >>> 0;
  }
  for (let i = 0; i < byteLength; i++) {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    out[i] = (seed >>> 0) & 0xff;
  }
  return out;
}

function buildCatalogEntry(spec: {
  key: string;
  name: string;
  mime: string;
  size: number;
  chunkSize: number;
  p2p: boolean;
  description: string;
  category: CatalogAsset['category'];
  recommendedMode: 'bulk' | 'sequential';
}): CatalogAsset {
  const chunkCount = Math.ceil(spec.size / spec.chunkSize);
  const allHashes = new Uint8Array(chunkCount * 32);

  // Use deterministic 256-byte digest seed per chunk to compute authentic SHA-256 hashes rapidly
  for (let i = 0; i < chunkCount; i++) {
    const sampleBytes = generateDeterministicChunkBytes(spec.key, i, 256);
    const digest = sha256Bytes(sampleBytes);
    allHashes.set(digest, i * 32);
  }

  const manifestDraft: Manifest = {
    v: 1,
    name: spec.name,
    mime: spec.mime,
    size: spec.size,
    chunkSize: spec.chunkSize,
    chunkCount,
    hashAlg: 'sha256',
    hashes: bytesToBase64(allHashes),
    urls: {
      cdn: `/api/origin/chunk/${spec.key}?source=cdn`,
      origin: `/api/origin/chunk/${spec.key}?source=origin`,
    },
    p2p: spec.p2p,
    version: '2026-10-15.1',
    sig: null,
  };

  const manifestRawJson = JSON.stringify(manifestDraft);
  const assetId: AssetId = `sha256-${sha256Hex(manifestRawJson)}`;

  return {
    key: spec.key,
    assetId,
    manifest: manifestDraft,
    manifestRawJson,
    description: spec.description,
    category: spec.category,
    recommendedMode: spec.recommendedMode,
  };
}

let cachedCatalog: CatalogAsset[] | null = null;

export function getDemoCatalog(): CatalogAsset[] {
  if (cachedCatalog) return cachedCatalog;
  cachedCatalog = [
    buildCatalogEntry({
      key: 'model-shard-03',
      name: 'model-shard-03.safetensors',
      mime: 'application/octet-stream',
      size: 83886080, // 80 MiB (320 chunks x 256 KiB)
      chunkSize: 262144,
      p2p: true,
      description: 'Llama-3.2 WebLLM FP16 Tensor Shard (320 chunks × 256 KiB, Spec Default Workload)',
      category: 'ML Weights',
      recommendedMode: 'bulk',
    }),
    buildCatalogEntry({
      key: 'whisper-wasm',
      name: 'whisper-v3-turbo-simd.wasm',
      mime: 'application/wasm',
      size: 50331648, // 48 MiB (192 chunks x 256 KiB)
      chunkSize: 262144,
      p2p: true,
      description: 'In-Browser ONNX / WebGPU Speech Runtime Binary (192 chunks × 256 KiB)',
      category: 'WASM Bundle',
      recommendedMode: 'bulk',
    }),
    buildCatalogEntry({
      key: 'hero-4k-stream',
      name: 'keynote-av1-4k-segment.mp4',
      mime: 'video/mp4',
      size: 16777216, // 16 MiB (64 chunks x 256 KiB)
      chunkSize: 262144,
      p2p: true,
      description: 'High-Bitrate AV1 Video Segment with Sequential Playhead Lookahead (64 chunks)',
      category: '4K Media',
      recommendedMode: 'sequential',
    }),
    buildCatalogEntry({
      key: 'brand-logo-svg',
      name: 'logo-mark.svg',
      mime: 'image/svg+xml',
      size: 8192, // 8 KiB (< minP2PSize 1 MiB -> policy forces CDN)
      chunkSize: 262144,
      p2p: false,
      description: 'Small 8 KB Vector Asset — Below 1 MiB Threshold (Verify Policy Stays on CDN)',
      category: 'Small Static',
      recommendedMode: 'bulk',
    }),
  ];
  return cachedCatalog;
}
