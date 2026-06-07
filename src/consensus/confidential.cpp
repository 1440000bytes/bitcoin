// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <consensus/confidential.h>

#include <primitives/transaction.h>

#include <secp256k1.h>
#include <secp256k1_generator.h>
#include <secp256k1_rangeproof.h>

#include <array>

namespace ct {

namespace {
//! Process-wide verification context for the confidential modules. The range
//! proof and Pedersen verifiers only need the static context's capabilities.
const secp256k1_context* VerifyContext()
{
    static secp256k1_context* const ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    return ctx;
}

//! Turn a CConfidentialValue into a parsed Pedersen commitment. Explicit values
//! are folded in as the zero-blind commitment v*H. Returns false on a null or
//! malformed value (fail closed).
bool ToCommitment(const secp256k1_context* ctx, const CConfidentialValue& v,
                  secp256k1_pedersen_commitment& out)
{
    if (v.IsExplicit()) {
        static const std::array<unsigned char, 32> zero_blind{};
        const uint64_t amount = static_cast<uint64_t>(v.GetAmount());
        return secp256k1_pedersen_commit(ctx, &out, zero_blind.data(), amount,
                                         secp256k1_generator_h) == 1;
    }
    if (v.IsCommitment()) {
        return secp256k1_pedersen_commitment_parse(ctx, &out, v.vch.data()) == 1;
    }
    return false; // null / malformed
}
} // namespace

bool VerifyValueBalance(std::span<const CConfidentialValue> inputs,
                        std::span<const CConfidentialValue> outputs)
{
    const secp256k1_context* ctx = VerifyContext();

    std::vector<secp256k1_pedersen_commitment> in_c(inputs.size());
    std::vector<secp256k1_pedersen_commitment> out_c(outputs.size());
    std::vector<const secp256k1_pedersen_commitment*> in_p, out_p;
    in_p.reserve(inputs.size());
    out_p.reserve(outputs.size());

    for (size_t i = 0; i < inputs.size(); ++i) {
        if (!ToCommitment(ctx, inputs[i], in_c[i])) return false;
        in_p.push_back(&in_c[i]);
    }
    for (size_t i = 0; i < outputs.size(); ++i) {
        if (!ToCommitment(ctx, outputs[i], out_c[i])) return false;
        out_p.push_back(&out_c[i]);
    }

    return secp256k1_pedersen_verify_tally(ctx, in_p.data(), in_p.size(),
                                           out_p.data(), out_p.size()) == 1;
}

bool VerifyRangeProof(const CConfidentialValue& commitment,
                      std::span<const unsigned char> rangeproof)
{
    if (!commitment.IsCommitment() || rangeproof.empty()) return false;
    const secp256k1_context* ctx = VerifyContext();

    secp256k1_pedersen_commitment commit;
    if (secp256k1_pedersen_commitment_parse(ctx, &commit, commitment.vch.data()) != 1) {
        return false;
    }
    uint64_t min_value = 0, max_value = 0;
    return secp256k1_rangeproof_verify(ctx, &min_value, &max_value, &commit,
                                       rangeproof.data(), rangeproof.size(),
                                       nullptr, 0, secp256k1_generator_h) == 1;
}

bool CheckConfidential(std::span<const CTxOut> inputs,
                       std::span<const CTxOut> outputs)
{
    // Every committed output must carry a valid range proof. Explicit outputs
    // (ordinary amounts and the explicit fee output) need none.
    for (const CTxOut& out : outputs) {
        if (out.nValue.IsCommitment()) {
            if (!VerifyRangeProof(out.nValue, out.rangeproof)) return false;
        }
    }

    std::vector<CConfidentialValue> in_vals, out_vals;
    in_vals.reserve(inputs.size());
    out_vals.reserve(outputs.size());
    for (const CTxOut& in : inputs) in_vals.push_back(in.nValue);
    for (const CTxOut& out : outputs) out_vals.push_back(out.nValue);

    return VerifyValueBalance(in_vals, out_vals);
}

} // namespace ct
