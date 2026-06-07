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

#include <compressor.h>
#include <consensus/confidential.h>
#include <primitives/confidential.h>
#include <primitives/transaction.h>
#include <random.h>
#include <streams.h>

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

// Phase 2a: the CConfidentialValue/Nonce wire format round-trips, and an
// explicit value built from a real Pedersen commitment serializes as a
// 33-byte commitment.
BOOST_AUTO_TEST_CASE(confidential_value_serialization)
{
    // Explicit value round-trips and preserves the amount.
    {
        CConfidentialValue v(CAmount{2'100'000'000'000'000}); // 21M BTC in sats
        BOOST_CHECK(v.IsExplicit());
        BOOST_CHECK_EQUAL(v.GetAmount(), CAmount{2'100'000'000'000'000});

        DataStream ss;
        ss << v;
        BOOST_CHECK_EQUAL(ss.size(), CConfidentialValue::EXPLICIT_SIZE);
        CConfidentialValue v2;
        ss >> v2;
        BOOST_CHECK(v2.IsExplicit());
        BOOST_CHECK(v == v2);
        BOOST_CHECK_EQUAL(v2.GetAmount(), CAmount{2'100'000'000'000'000});
    }

    // Null round-trips to a single zero prefix byte.
    {
        CConfidentialValue v;
        BOOST_CHECK(v.IsNull());
        DataStream ss;
        ss << v;
        BOOST_CHECK_EQUAL(ss.size(), 1U);
        CConfidentialValue v2(CAmount{5});
        ss >> v2;
        BOOST_CHECK(v2.IsNull());
    }

    // A serialized Pedersen commitment becomes a 33-byte confidential value.
    {
        ZKPContext z;
        unsigned char blind[32];
        RandBlind(blind);
        secp256k1_pedersen_commitment commit;
        BOOST_REQUIRE(secp256k1_pedersen_commit(z.ctx, &commit, blind, 99,
                                                secp256k1_generator_h));
        unsigned char ser[33];
        BOOST_REQUIRE(secp256k1_pedersen_commitment_serialize(z.ctx, ser, &commit));

        CConfidentialValue v;
        v.SetToCommitment(ser);
        BOOST_CHECK(v.IsCommitment());
        BOOST_CHECK(!v.IsExplicit());

        DataStream ss;
        ss << v;
        BOOST_CHECK_EQUAL(ss.size(), CConfidentialValue::COMMITMENT_SIZE);
        CConfidentialValue v2;
        ss >> v2;
        BOOST_CHECK(v2.IsCommitment());
        BOOST_CHECK(v == v2);
    }
}

BOOST_AUTO_TEST_CASE(confidential_nonce_serialization)
{
    CConfidentialNonce n;
    BOOST_CHECK(n.IsNull());

    unsigned char pubkey[33];
    pubkey[0] = 2;
    for (int i = 1; i < 33; ++i) pubkey[i] = static_cast<unsigned char>(i);
    n.SetToPubKey(pubkey);
    BOOST_CHECK(n.IsCommitment());

    DataStream ss;
    ss << n;
    BOOST_CHECK_EQUAL(ss.size(), CConfidentialNonce::COMMITMENT_SIZE);
    CConfidentialNonce n2;
    ss >> n2;
    BOOST_CHECK(n == n2);
}

namespace {
// Build a committed CTxOut for `value` using `blind`, attach a valid range proof,
// and (optionally) give it a non-empty scriptPubKey.
CTxOut MakeBlindedOutput(ZKPContext& z, uint64_t value, const unsigned char blind[32],
                         bool spendable = true)
{
    secp256k1_pedersen_commitment commit;
    BOOST_REQUIRE(secp256k1_pedersen_commit(z.ctx, &commit, blind, value, secp256k1_generator_h));
    unsigned char ser[33];
    BOOST_REQUIRE(secp256k1_pedersen_commitment_serialize(z.ctx, ser, &commit));

    CTxOut out;
    out.nValue.SetToCommitment(ser);
    if (spendable) out.scriptPubKey << OP_TRUE;

    unsigned char proof[5134];
    size_t plen = sizeof(proof);
    BOOST_REQUIRE(secp256k1_rangeproof_sign(z.ctx, proof, &plen, 0, &commit, blind, blind,
                                            0, 0, value, nullptr, 0, nullptr, 0,
                                            secp256k1_generator_h));
    out.rangeproof.assign(proof, proof + plen);
    return out;
}
} // namespace

// Phase 3: a hand-built confidential transaction with committed inputs and
// outputs balances under ct::CheckConfidential, and tampering breaks it.
BOOST_AUTO_TEST_CASE(check_confidential_transaction)
{
    ZKPContext z;

    // One blinded input worth 100. Outputs: blinded 70 + blinded 29 + explicit
    // fee 1 (empty script). 100 == 70 + 29 + 1. The output blinds must sum to the
    // input blind (the fee is explicit -> zero blind); solve the last one.
    const uint64_t in_val = 100, out0 = 70, out1 = 29, fee = 1;

    unsigned char zero[32] = {0};
    unsigned char b_in[32], b_out0[32], b_out1[32];
    RandBlind(b_in);
    RandBlind(b_out0);
    std::memset(b_out1, 0, 32);

    // Solve the LAST blind so the commitments tally. The solved blind must land
    // on a committed output (b_out1), NOT the explicit fee (which is zero-blind),
    // so order the elements [in | out0, fee, out1] with out1 last.
    const uint64_t values[4] = {in_val, out0, fee, out1};
    unsigned char b_fee[32] = {0};
    const unsigned char* gen_blinds[4] = {zero, zero, zero, zero};
    unsigned char* blind_ptrs[4] = {b_in, b_out0, b_fee, b_out1};
    BOOST_REQUIRE(secp256k1_pedersen_blind_generator_blind_sum(
        z.ctx, values, gen_blinds, blind_ptrs, /*n_total=*/4, /*n_inputs=*/1));

    std::vector<CTxOut> inputs{MakeBlindedOutput(z, in_val, b_in)};
    std::vector<CTxOut> outputs{
        MakeBlindedOutput(z, out0, b_out0),
        MakeBlindedOutput(z, out1, b_out1),
    };
    CTxOut fee_out; // explicit, empty script
    fee_out.nValue = CAmount{static_cast<int64_t>(fee)};
    outputs.push_back(fee_out);

    BOOST_CHECK(ct::CheckConfidential(inputs, outputs));

    // Tamper 1: corrupt a range proof -> output proof check fails.
    {
        auto bad = outputs;
        bad[0].rangeproof[bad[0].rangeproof.size() / 2] ^= 0x01;
        BOOST_CHECK(!ct::CheckConfidential(inputs, bad));
    }

    // Tamper 2: drop the fee output -> balance no longer tallies (100 != 99).
    {
        std::vector<CTxOut> bad{outputs[0], outputs[1]};
        BOOST_CHECK(!ct::CheckConfidential(inputs, bad));
    }

    // Sanity: an output committing to an inflated amount (re-blinded for 71)
    // breaks the tally even though its own range proof is valid.
    {
        unsigned char b_cheat[32];
        RandBlind(b_cheat);
        auto bad = outputs;
        bad[0] = MakeBlindedOutput(z, out0 + 1, b_cheat);
        BOOST_CHECK(!ct::CheckConfidential(inputs, bad));
    }
}

// Phase 4: the UTXO compressor preserves both explicit amounts (legacy compact
// encoding) and Pedersen commitments (full 33 bytes) across a round trip.
BOOST_AUTO_TEST_CASE(utxo_compression_roundtrip)
{
    ZKPContext z;

    // Explicit value: compresses and restores exactly.
    {
        CTxOut out(CAmount{1234500000}, CScript() << OP_TRUE);
        DataStream ss;
        ss << Using<TxOutCompression>(out);
        CTxOut restored;
        ss >> Using<TxOutCompression>(restored);
        BOOST_CHECK(restored.nValue.IsExplicit());
        BOOST_CHECK_EQUAL(restored.nValue.GetAmount(), CAmount{1234500000});
        BOOST_CHECK(restored.scriptPubKey == out.scriptPubKey);
    }

    // Committed value: the commitment survives the UTXO encoding intact, so the
    // spend-time balance tally can use it.
    {
        unsigned char blind[32];
        RandBlind(blind);
        secp256k1_pedersen_commitment commit;
        BOOST_REQUIRE(secp256k1_pedersen_commit(z.ctx, &commit, blind, 7777,
                                                secp256k1_generator_h));
        unsigned char ser[33];
        BOOST_REQUIRE(secp256k1_pedersen_commitment_serialize(z.ctx, ser, &commit));

        CTxOut out;
        out.nValue.SetToCommitment(ser);
        out.scriptPubKey << OP_TRUE;

        DataStream ss;
        ss << Using<TxOutCompression>(out);
        CTxOut restored;
        ss >> Using<TxOutCompression>(restored);
        BOOST_CHECK(restored.nValue.IsCommitment());
        BOOST_CHECK(restored.nValue == out.nValue);
        BOOST_CHECK(restored.scriptPubKey == out.scriptPubKey);
    }
}

BOOST_AUTO_TEST_SUITE_END()
