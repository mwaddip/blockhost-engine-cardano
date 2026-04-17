/**
 * Compare signup-engine Plutus Data encoding between the legacy inline JS
 * and the cmttk-based port.
 *
 * Runs the new encoder (src/signup/encoder.ts, via cmttk/cbor) against fixed
 * test vectors and prints the CBOR hex. To check equivalence, paste the same
 * inputs into the browser console of the legacy signup-engine.js page and
 * compare its `datumCbor` output to the hex printed here.
 *
 * Usage: npx tsx scripts/compare-signup-datum.ts
 */

import {
    encodePlutusSubscriptionDatum,
    plutusConstr,
    cborBytesChunked,
    cborInt,
    bytesToHex,
} from "../src/signup/encoder.js";

interface Vector {
    name: string;
    hex: string;
    expected?: string; // only set where the legacy encoder's output is known
}

const out: Vector[] = [];

// ── Primitive vectors ────────────────────────────────────────────────────

out.push({
    name: "empty Constr(0, [])",
    hex: bytesToHex(plutusConstr(0, [])),
    expected: "d87980", // tag 121 + definite empty array
});

out.push({
    name: "Constr(0, [42])",
    hex: bytesToHex(plutusConstr(0, [cborInt(42)])),
    expected: "d8799f182aff", // tag 121 + indef [0x18 0x2a] + break
});

out.push({
    name: "Constr(1, [])",
    hex: bytesToHex(plutusConstr(1, [])),
    expected: "d87a80",
});

out.push({
    name: "Constr(7, [42]) — uses tag 102",
    hex: bytesToHex(plutusConstr(7, [cborInt(42)])),
    expected: "d86682079f182aff",
});

// ── Chunked bytes ────────────────────────────────────────────────────────

// 64 bytes = borderline, stays definite-length
const bytes64 = "aa".repeat(64);
out.push({
    name: "cborBytesChunked(64-byte)",
    hex: bytesToHex(cborBytesChunked(bytes64)),
});

// 65 bytes = triggers indefinite chunking
const bytes65 = "aa".repeat(65);
out.push({
    name: "cborBytesChunked(65-byte) — indefinite",
    hex: bytesToHex(cborBytesChunked(bytes65)),
});

// ECIES ciphertext length (~ 93 bytes = eph(65) + iv(12) + short msg ≥ 16)
const ecies = "bb".repeat(93);
out.push({
    name: "cborBytesChunked(93-byte ECIES-ish) — indefinite",
    hex: bytesToHex(cborBytesChunked(ecies)),
});

// ── Full subscription datum ──────────────────────────────────────────────

// Fixed test vector approximating a realistic subscription
const datumHex = encodePlutusSubscriptionDatum({
    planId: 1,
    expiry: 1733097600000n,
    subscriberKeyHash: "2dbdd41304e95e4a1846c045328d746bf2267a0a619ec55976e7beb1",
    amountRemaining: 150000000n,
    ratePerInterval: 5000000n,
    intervalMs: 86400000n,
    lastCollected: 1730505600000n,
    payPolicyId: "",        // ADA
    payAssetName: "",
    beaconPolicyId: "9abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
    userEncrypted: "cc".repeat(128), // 128 bytes ≈ realistic ECIES blob → indef-chunked
    creationHeight: 10000000,
});

out.push({
    name: "encodePlutusSubscriptionDatum(ADA plan, 128B userEncrypted)",
    hex: datumHex,
});

// ── Print ─────────────────────────────────────────────────────────────────

console.log("# signup-engine datum encoder — cmttk-based port output");
console.log();
console.log("Paste the same inputs into the legacy signup-engine.js runtime");
console.log("(via browser console on the signup page) and compare the hex.");
console.log();

let pass = 0;
let fail = 0;
for (const v of out) {
    console.log(`## ${v.name}`);
    console.log(`   hex: ${v.hex}`);
    if (v.expected) {
        const ok = v.hex === v.expected;
        console.log(`   expected: ${v.expected}  ${ok ? "✓" : "✗ MISMATCH"}`);
        if (ok) pass++; else fail++;
    }
    console.log();
}

// Sanity asserts — the original signup-engine.js explicitly checks this.
console.log("## Sanity check: subscription datum starts with d8799f");
const prefixOk = datumHex.startsWith("d8799f");
console.log(`   ${prefixOk ? "✓" : "✗"} datum hex prefix = ${datumHex.slice(0, 6)}`);
if (prefixOk) pass++; else fail++;

console.log();
console.log(`Summary: ${pass} pass, ${fail} fail (of vectors with expected values)`);
process.exit(fail === 0 ? 0 : 1);
