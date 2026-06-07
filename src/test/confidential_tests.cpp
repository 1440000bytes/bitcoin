// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Phase 1b: prove the secp256k1-zkp crypto links and behaves as Confidential
// Transactions consensus will rely on:
//   * Pedersen value commitments  C = v*H + r*G
//   * range proofs that hide v while proving v in [0, 2^64)
//   * the homomorphic "balance tally": sum(inputs) == sum(outputs) + fee*H
// These are exactly the primitives Phase 3's CheckTxInputs replacement calls.

#include <random.h>

#include <cstring>

#include <boost/test/unit_test.hpp>

#include <secp256k1.h>
#include <secp256k1_generator.h>
#include <secp256k1_rangeproof.h>

namespace {
struct ZKPContext {
    secp256k1_context* ctx;
    ZKPContext() : ctx(secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)) {}
    ~ZKPContext() { secp256k1_context_destroy(ctx); }
};

// Fill a 32-byte blinding factor from the test PRNG (deterministic under the
// test seed; never use the test PRNG for real money).
void RandBlind(unsigned char out[32])
{
    GetRandBytes(std::span<unsigned char>(out, 32));
}
} // namespace

BOOST_AUTO_TEST_SUITE(confidential_tests)

// A single commitment + range proof round-trips: commit, prove, verify, and the
// proof recovers the original [min,max] range.
BOOST_AUTO_TEST_CASE(commit_and_rangeproof_roundtrip)
{
    ZKPContext z;
    const uint64_t value = 1'234'567;

    unsigned char blind[32];
    RandBlind(blind);

    secp256k1_pedersen_commitment commit;
    BOOST_REQUIRE(secp256k1_pedersen_commit(z.ctx, &commit, blind, value,
                                            secp256k1_generator_h));

    unsigned char proof[5134];
    size_t proof_len = sizeof(proof);
    BOOST_REQUIRE(secp256k1_rangeproof_sign(
        z.ctx, proof, &proof_len, /*min_value=*/0, &commit, blind,
        /*nonce=*/blind, /*exp=*/0, /*min_bits=*/0, value,
        /*message=*/nullptr, 0, /*extra_commit=*/nullptr, 0,
        secp256k1_generator_h));

    uint64_t min_value = 0, max_value = 0;
    BOOST_CHECK(secp256k1_rangeproof_verify(z.ctx, &min_value, &max_value,
                                            &commit, proof, proof_len,
                                            nullptr, 0, secp256k1_generator_h));
    BOOST_CHECK(min_value <= value);
    BOOST_CHECK(max_value >= value);
}

// A forged commitment to a value with the WRONG range-proof bounds must fail to
// verify against a tampered proof buffer. This is the inflation guard.
BOOST_AUTO_TEST_CASE(tampered_rangeproof_rejected)
{
    ZKPContext z;
    unsigned char blind[32];
    RandBlind(blind);

    secp256k1_pedersen_commitment commit;
    BOOST_REQUIRE(secp256k1_pedersen_commit(z.ctx, &commit, blind, 42,
                                            secp256k1_generator_h));
    unsigned char proof[5134];
    size_t proof_len = sizeof(proof);
    BOOST_REQUIRE(secp256k1_rangeproof_sign(
        z.ctx, proof, &proof_len, 0, &commit, blind, blind, 0, 0, 42,
        nullptr, 0, nullptr, 0, secp256k1_generator_h));

    // Flip a byte in the middle of the proof.
    proof[proof_len / 2] ^= 0x01;

    uint64_t min_value = 0, max_value = 0;
    BOOST_CHECK(!secp256k1_rangeproof_verify(z.ctx, &min_value, &max_value,
                                             &commit, proof, proof_len,
                                             nullptr, 0, secp256k1_generator_h));
}

// The homomorphic balance check that replaces value_in - value_out == fee.
// Build inputs (10, 7) and outputs (5, 9) with an explicit fee of 3; the
// blinding factors must be chosen so the commitments tally exactly.
BOOST_AUTO_TEST_CASE(pedersen_balance_tally)
{
    ZKPContext z;

    // Layout: [in0, in1 | fee, out0, out1]. First n_inputs are inputs (positive),
    // the rest are outputs (negative). 10 + 7 == 3 + 5 + 9.
    const uint64_t values[5] = {10, 7, 3, 5, 9};
    const size_t n_total = 5, n_inputs = 2;

    unsigned char zero[32] = {0};
    unsigned char blinds[5][32];
    RandBlind(blinds[0]);                 // in0  (free)
    RandBlind(blinds[1]);                 // in1  (free)
    std::memcpy(blinds[2], zero, 32);     // fee  (explicit -> zero blind)
    RandBlind(blinds[3]);                 // out0 (free)
    std::memset(blinds[4], 0, 32);        // out1 (solved below)

    // All elements live on the single generator H, so the per-element generator
    // blinds are all zero. The call solves blinds[4] so the commitments tally.
    const unsigned char* gen_blinds[5] = {zero, zero, zero, zero, zero};
    unsigned char* blind_ptrs[5] = {blinds[0], blinds[1], blinds[2], blinds[3], blinds[4]};
    BOOST_REQUIRE(secp256k1_pedersen_blind_generator_blind_sum(
        z.ctx, values, gen_blinds, blind_ptrs, n_total, n_inputs));

    secp256k1_pedersen_commitment c[5];
    for (int i = 0; i < 5; ++i) {
        BOOST_REQUIRE(secp256k1_pedersen_commit(z.ctx, &c[i], blinds[i],
                                                values[i], secp256k1_generator_h));
    }
    const secp256k1_pedersen_commitment* pos[2] = {&c[0], &c[1]};
    const secp256k1_pedersen_commitment* neg[3] = {&c[2], &c[3], &c[4]};
    BOOST_CHECK(secp256k1_pedersen_verify_tally(z.ctx, pos, 2, neg, 3));

    // A dishonest output (inflate out0 by 1) must break the tally.
    secp256k1_pedersen_commitment cheat;
    BOOST_REQUIRE(secp256k1_pedersen_commit(z.ctx, &cheat, blinds[3],
                                            values[3] + 1, secp256k1_generator_h));
    const secp256k1_pedersen_commitment* neg_cheat[3] = {&c[2], &cheat, &c[4]};
    BOOST_CHECK(!secp256k1_pedersen_verify_tally(z.ctx, pos, 2, neg_cheat, 3));
}

BOOST_AUTO_TEST_SUITE_END()
