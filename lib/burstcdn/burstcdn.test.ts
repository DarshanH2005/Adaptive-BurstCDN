/**
 * Adaptive BurstCDN — Fast-Feedback Unit & Property Test Suite (node:test)
 * Verifies Invariants I1, I2, I3, Wire Codec, Bitfield, Circuit Breakers, Scheduler Cost Model, and Benchmark Bounds.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  Bitfield,
  BurstScheduler,
  ChunkReassembler,
  ChunkVerifier,
  DEFAULT_BURST_CONFIG,
  OriginCircuitBreaker,
  PeerStat,
  SwarmCircuitBreaker,
  WireFrameType,
  computeBdpWindow,
  decodeWireFrame,
  encodeWireFrame,
  fragmentChunkToFrames,
  generateDeterministicChunkBytes,
  getDemoCatalog,
  sha256Bytes,
  shouldInitiateOffer,
  verifyManifestBytes,
} from './core.ts';
import { runBenchmarkSuite } from './simulator.ts';

test('Wire Protocol: 15-byte binary frame header round-trips and fragments chunks <= 16 KiB', () => {
  const payload = new Uint8Array([10, 20, 30, 40, 255]);
  const encoded = encodeWireFrame({
    type: WireFrameType.REQUEST,
    swarm: 7,
    chunk: 319,
    offset: 0,
    total: 262144,
    payload,
  });

  assert.equal(encoded.byteLength, 15 + payload.byteLength);
  const decoded = decodeWireFrame(encoded);
  assert.equal(decoded.type, WireFrameType.REQUEST);
  assert.equal(decoded.swarm, 7);
  assert.equal(decoded.chunk, 319);
  assert.equal(decoded.offset, 0);
  assert.equal(decoded.total, 262144);
  assert.deepEqual(decoded.payload, payload);

  // Fragment 64 KiB chunk into <= 16 KiB frames and reassemble out-of-order with duplicates
  const rawChunk = generateDeterministicChunkBytes('test-asset', 4, 65536);
  const frames = fragmentChunkToFrames(1, 4, rawChunk, 16384);
  assert.ok(frames.length >= 5, 'Should split 64 KiB into at least 5 frames of <= 16 KiB');
  for (const f of frames) {
    assert.ok(15 + f.payload.byteLength <= 16384);
  }

  const reassembler = new ChunkReassembler(8);
  // Push frames in reverse order + duplicate first frame
  const reversed = [...frames].reverse();
  reassembler.pushFragment(frames[0]); // duplicate early
  let completed: Uint8Array | null = null;
  for (const f of reversed) {
    const res = reassembler.pushFragment(f);
    if (res) completed = res;
  }
  assert.ok(completed, 'Reassembler must produce complete chunk once all unique fragments arrive');
  assert.deepEqual(completed, rawChunk);
  assert.equal(reassembler.bufferedBytes, 0);
});

test('Glare avoidance: lexicographically smaller peerId initiates WebRTC offer', () => {
  assert.equal(shouldInitiateOffer('peer-alpha', 'peer-zeta'), true);
  assert.equal(shouldInitiateOffer('peer-zeta', 'peer-alpha'), false);
  assert.throws(() => shouldInitiateOffer('peer-same', 'peer-same'));
});

test('Bitfield: bit-packing, intersectionMissing, and byte serialization round-trip', () => {
  const bfA = new Bitfield(320);
  const bfB = new Bitfield(320);

  bfA.set(0);
  bfA.set(7);
  bfA.set(8);
  bfA.set(319);
  assert.equal(bfA.count(), 4);
  assert.equal(bfA.has(7), true);
  assert.equal(bfA.has(6), false);

  bfB.set(6);
  bfB.set(7);
  bfB.set(100);

  // A is missing 6 and 100 which B has
  const canFetchFromB = bfA.intersectionMissing(bfB);
  assert.deepEqual(canFetchFromB, [6, 100]);

  const serialized = bfA.toBytes();
  const restored = Bitfield.fromBytes(320, serialized);
  assert.equal(restored.count(), 4);
  assert.equal(restored.has(319), true);
  assert.equal(restored.has(8), true);
});

test('Invariant I1 & I2: Self-certifying manifest & SHA-256 ChunkVerifier reject corrupted bytes', () => {
  const catalog = getDemoCatalog();
  const modelAsset = catalog[0];

  // Verify self-certifying manifest matches assetId
  const validManifestCheck = verifyManifestBytes(modelAsset.manifestRawJson, modelAsset.assetId);
  assert.equal(validManifestCheck.ok, true);

  // Tamper with manifest -> must fail self-certifying check
  const tamperedCheck = verifyManifestBytes(
    modelAsset.manifestRawJson.replace('"p2p":true', '"p2p":false'),
    modelAsset.assetId
  );
  assert.equal(tamperedCheck.ok, false);

  // Verify authentic chunk 0 bytes vs corrupted chunk 0 bytes
  const verifier = new ChunkVerifier(modelAsset.manifest);
  const authenticSample = generateDeterministicChunkBytes(modelAsset.key, 0, 256);
  const verified = verifier.verifyChunk(0, authenticSample);
  assert.ok(verified !== null, 'Authentic chunk bytes must pass SHA-256 check');

  const corruptedSample = new Uint8Array(authenticSample);
  corruptedSample[12] ^= 0xff; // Flip 1 byte
  const rejected = verifier.verifyChunk(0, corruptedSample);
  assert.equal(rejected, null, 'Corrupted chunk bytes MUST be rejected by SHA-256 verifier');
});

test('Circuit Breakers: Origin trips on high TTFB (>400ms) or errors (>20%) and recovers via HALF_OPEN', () => {
  const breaker = new OriginCircuitBreaker(DEFAULT_BURST_CONFIG);
  assert.equal(breaker.getState(0), 'CLOSED');

  // Record 6 errors out of 10 requests (60% > 20% threshold)
  for (let i = 0; i < 10; i++) {
    breaker.recordSample(110, i < 6, i * 100);
  }
  assert.equal(breaker.getState(1000), 'OPEN', 'Origin breaker must trip to OPEN on high error rate');

  // After cooldown (5000ms), transitions to HALF_OPEN
  assert.equal(breaker.getState(6500), 'HALF_OPEN');

  // Two healthy probes close the breaker
  breaker.recordSample(75, false, 6600);
  breaker.recordSample(80, false, 6700);
  assert.equal(breaker.getState(6700), 'CLOSED');

  // Swarm breaker trips after 3 hash failures in 30s
  const swarmBreaker = new SwarmCircuitBreaker(DEFAULT_BURST_CONFIG);
  swarmBreaker.recordPeerOutcome(false, true, 100);
  swarmBreaker.recordPeerOutcome(false, true, 200);
  assert.equal(swarmBreaker.getState(200), 'CLOSED');
  swarmBreaker.recordPeerOutcome(false, true, 300);
  assert.equal(swarmBreaker.getState(300), 'OPEN');
});

test('Scheduler: cost model, small-asset CDN policy, TURN relay rejection, and peer banning after 2 hash fails', () => {
  const catalog = getDemoCatalog();
  const largeAsset = catalog[0]; // 80 MB, p2p: true
  const smallSvg = catalog[3]; // 8 KB, p2p: false

  const scheduler = new BurstScheduler(DEFAULT_BURST_CONFIG);

  const bfLarge = new Bitfield(largeAsset.manifest.chunkCount);
  bfLarge.set(0);
  bfLarge.set(1);

  const fastDirectPeer: PeerStat = {
    peerId: 'peer-direct-1',
    region: 'us-east',
    viaRelay: false,
    rttEwmaMs: 25,
    tputEwmaBps: 10 * 1024 * 1024, // 10 MB/s
    inflight: 0,
    window: computeBdpWindow(10 * 1024 * 1024, 25, 262144),
    successStreak: 3,
    totalSuccesses: 5,
    timeouts: 0,
    hashFails: 0,
    bytesDown: 0,
    bytesUp: 0,
    banned: false,
    rejectedRelay: false,
    bitfield: bfLarge,
  };

  const turnRelayPeer: PeerStat = {
    ...fastDirectPeer,
    peerId: 'peer-turn-relay',
    viaRelay: true,
    rejectedRelay: false,
  };

  // 1. Small asset (< 1 MiB / p2p:false) must choose CDN even if peer has chunk
  const smallDecision = scheduler.chooseSourceForChunk({
    manifest: smallSvg.manifest,
    chunkIndex: 0,
    chunkByteSize: 8192,
    peers: [fastDirectPeer],
    cdnStat: { rttMs: 30, tputBps: 12 * 1024 * 1024, inflight: 0, healthy: true },
    originStat: { rttMs: 80, tputBps: 5 * 1024 * 1024, inflight: 0 },
    slackMode: 'normal',
    nowMs: 1000,
  });
  assert.equal(smallDecision.chosen.kind, 'cdn');

  // 2. Large asset with TURN relay peer only -> TURN peer rejected (ADR-006), falls back to CDN
  const relayDecision = scheduler.chooseSourceForChunk({
    manifest: largeAsset.manifest,
    chunkIndex: 0,
    chunkByteSize: 262144,
    peers: [turnRelayPeer],
    cdnStat: { rttMs: 30, tputBps: 12 * 1024 * 1024, inflight: 0, healthy: true },
    originStat: { rttMs: 80, tputBps: 5 * 1024 * 1024, inflight: 0 },
    slackMode: 'normal',
    nowMs: 1000,
  });
  assert.equal(relayDecision.chosen.kind, 'cdn');
  assert.equal(scheduler.relayRejectedCount, 1);

  // 3. Large asset with healthy direct peer within slack (1.5x) -> chooses peer (cost=0 < cdn cost=1)
  const peerDecision = scheduler.chooseSourceForChunk({
    manifest: largeAsset.manifest,
    chunkIndex: 0,
    chunkByteSize: 262144,
    peers: [fastDirectPeer],
    cdnStat: { rttMs: 22, tputBps: 12 * 1024 * 1024, inflight: 0, healthy: true },
    originStat: { rttMs: 80, tputBps: 5 * 1024 * 1024, inflight: 0 },
    slackMode: 'normal',
    nowMs: 1000,
  });
  assert.equal(peerDecision.chosen.kind, 'peer');
  assert.equal(peerDecision.chosen.id, 'peer-direct-1');

  // 4. Two hash failures ban the peer for the session (Section 7.3)
  scheduler.recordPeerTransfer(fastDirectPeer, {
    ok: true,
    hashOk: false,
    bytes: 262144,
    rttMs: 25,
    durMs: 30,
    chunkSize: 262144,
    nowMs: 1100,
  });
  assert.equal(fastDirectPeer.banned, false);
  scheduler.recordPeerTransfer(fastDirectPeer, {
    ok: true,
    hashOk: false,
    bytes: 262144,
    rttMs: 25,
    durMs: 30,
    chunkSize: 262144,
    nowMs: 1200,
  });
  assert.equal(fastDirectPeer.banned, true, 'Peer must be banned after 2 hash failures');
});

test('Benchmark Suite: respects theoretical ceiling offload <= 1 - 1/N and zero corrupt chunks accepted', () => {
  const s1 = runBenchmarkSuite({
    scenarioId: 'S1',
    tier: 'Tier A (Real Browsers)',
    seed: 42,
  });
  for (const pt of s1.points) {
    assert.ok(
      pt.adaptiveOffloadPct <= pt.theoreticalCeilingPct + 0.001,
      `Offload ${pt.adaptiveOffloadPct}% at N=${pt.n} must not exceed theoretical ceiling ${pt.theoreticalCeilingPct}%`
    );
    assert.equal(pt.acceptedCorruptChunks, 0);
  }
  const n100 = s1.points.find((p) => p.n === 100)!;
  assert.ok(n100.adaptiveOffloadPct > 80, 'S1 at N=100 should achieve >80% server egress offload');
  assert.ok(n100.adaptiveP95Sec < n100.httpP95Sec, 'Adaptive P95 must beat constrained HTTP-only P95');
});
