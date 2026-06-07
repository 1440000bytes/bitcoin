// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <blind.h>

#include <random.h>

#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_generator.h>
#include <secp256k1_rangeproof.h>

#include <array>
#include <cstring>

namespace blinding {

namespace {
//! Process-wide signing+verifying context for the blinding crypto.
secp256k1_context* BlindContext()
{
    static secp256k1_context* const ctx = [] {
        secp256k1_context* c = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        // Randomize to harden against side channels (best-effort).
        std::array<unsigned char, 32> seed;
        GetStrongRandBytes(seed);
        secp256k1_context_randomize(c, seed.data());
        return c;
    }();
    return ctx;
}

const unsigned char* RawBytes(const CKey& key)
{
    return reinterpret_cast<const unsigned char*>(key.data());
}

//! Compute the shared ECDH secret used as the range-proof nonce, given an
//! ephemeral pubkey (the output nonce) and a private key.
bool DeriveNonce(secp256k1_context* ctx, const CPubKey& ephemeral_pubkey,
                 const CKey& key, std::array<unsigned char, 32>& nonce_out)
{
    secp256k1_pubkey pub;
    if (secp256k1_ec_pubkey_parse(ctx, &pub, ephemeral_pubkey.data(), ephemeral_pubkey.size()) != 1) {
        return false;
    }
    return secp256k1_ecdh(ctx, nonce_out.data(), &pub, RawBytes(key), nullptr, nullptr) == 1;
}
} // namespace

bool BlindTransaction(const std::vector<CAmount>& input_amounts,
                      const std::vector<uint256>& input_blinds,
                      CMutableTransaction& tx,
                      const std::vector<size_t>& outputs_to_blind,
                      const std::vector<CPubKey>& receiver_blind_pubkeys)
{
    if (outputs_to_blind.empty()) return false;
    if (outputs_to_blind.size() != receiver_blind_pubkeys.size()) return false;
    if (input_amounts.size() != input_blinds.size()) return false;

    secp256k1_context* ctx = BlindContext();

    // Assemble the blind-sum solve. The solver balances the commitment blinds by
    // overwriting the LAST blinding factor, so the ordering must place a blinded
    // output last: [inputs | explicit outputs | blinded outputs]. Explicit
    // outputs (e.g. the fee) carry a zero blind and only contribute their value.
    std::vector<uint64_t> values;
    std::vector<std::array<unsigned char, 32>> blinds; // owns the buffers
    const size_t n_inputs = input_amounts.size();

    for (size_t i = 0; i < input_amounts.size(); ++i) {
        values.push_back(static_cast<uint64_t>(input_amounts[i]));
        std::array<unsigned char, 32> b{};
        std::memcpy(b.data(), input_blinds[i].data(), 32);
        blinds.push_back(b);
    }

    // Explicit (non-blinded) outputs first.
    std::vector<size_t> blind_set(outputs_to_blind.begin(), outputs_to_blind.end());
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        const bool is_blinded = std::find(blind_set.begin(), blind_set.end(), i) != blind_set.end();
        if (is_blinded) continue;
        if (!tx.vout[i].nValue.IsExplicit()) return false;
        values.push_back(static_cast<uint64_t>(tx.vout[i].nValue.GetAmount()));
        blinds.push_back(std::array<unsigned char, 32>{}); // zero blind
    }
    // Then the blinded outputs, the last of which is solved.
    const size_t first_blinded_idx = values.size();
    for (size_t k = 0; k < blind_set.size(); ++k) {
        const CTxOut& out = tx.vout[blind_set[k]];
        if (!out.nValue.IsExplicit()) return false;
        values.push_back(static_cast<uint64_t>(out.nValue.GetAmount()));
        std::array<unsigned char, 32> b{};
        if (k + 1 < blind_set.size()) {
            GetStrongRandBytes(b); // free blind
        } // else leave zero; solved below
        blinds.push_back(b);
    }

    // Solve the final blind so the commitments tally.
    std::vector<const unsigned char*> gen_blinds(values.size());
    static const std::array<unsigned char, 32> zero{};
    for (size_t i = 0; i < values.size(); ++i) gen_blinds[i] = zero.data();
    std::vector<unsigned char*> blind_ptrs(values.size());
    for (size_t i = 0; i < values.size(); ++i) blind_ptrs[i] = blinds[i].data();

    if (secp256k1_pedersen_blind_generator_blind_sum(
            ctx, values.data(), gen_blinds.data(), blind_ptrs.data(),
            values.size(), n_inputs) != 1) {
        return false;
    }

    // Build each blinded output: commitment, ECDH nonce, range proof.
    for (size_t k = 0; k < blind_set.size(); ++k) {
        CTxOut& out = tx.vout[blind_set[k]];
        const uint64_t value = static_cast<uint64_t>(out.nValue.GetAmount());
        const unsigned char* blind = blinds[first_blinded_idx + k].data();

        secp256k1_pedersen_commitment commit;
        if (secp256k1_pedersen_commit(ctx, &commit, blind, value, secp256k1_generator_h) != 1) {
            return false;
        }
        unsigned char ser[33];
        if (secp256k1_pedersen_commitment_serialize(ctx, ser, &commit) != 1) return false;
        out.nValue.SetToCommitment(ser);

        // Ephemeral key -> ECDH shared secret as the proof nonce; publish the
        // ephemeral pubkey as the output nonce so the receiver can reconstruct it.
        CKey ephemeral;
        ephemeral.MakeNewKey(/*fCompressed=*/true);
        const CPubKey eph_pub = ephemeral.GetPubKey();

        // Shared secret = ECDH(ephemeral_priv, receiver_pub). The receiver later
        // recomputes the identical secret as ECDH(receiver_priv, ephemeral_pub).
        secp256k1_pubkey recv;
        if (secp256k1_ec_pubkey_parse(ctx, &recv, receiver_blind_pubkeys[k].data(),
                                      receiver_blind_pubkeys[k].size()) != 1) {
            return false;
        }
        std::array<unsigned char, 32> nonce;
        if (secp256k1_ecdh(ctx, nonce.data(), &recv, RawBytes(ephemeral), nullptr, nullptr) != 1) {
            return false;
        }

        unsigned char proof[5134];
        size_t plen = sizeof(proof);
        if (secp256k1_rangeproof_sign(ctx, proof, &plen, /*min_value=*/0, &commit,
                                      blind, nonce.data(), /*exp=*/0, /*min_bits=*/0,
                                      value, nullptr, 0, nullptr, 0,
                                      secp256k1_generator_h) != 1) {
            return false;
        }
        out.rangeproof.assign(proof, proof + plen);
        out.nNonce.SetToPubKey(std::span<const unsigned char>(eph_pub.data(), eph_pub.size()));
    }

    return true;
}

std::optional<std::pair<CAmount, uint256>> UnblindOutput(const CTxOut& out, const CKey& blinding_key)
{
    if (!out.nValue.IsCommitment() || out.nNonce.IsNull() || out.rangeproof.empty()) {
        return std::nullopt;
    }
    secp256k1_context* ctx = BlindContext();

    // The output nonce is the sender's ephemeral pubkey. ECDH it with our key.
    CPubKey eph_pub(out.nNonce.vch.begin(), out.nNonce.vch.end());
    if (!eph_pub.IsValid()) return std::nullopt;
    std::array<unsigned char, 32> nonce;
    if (!DeriveNonce(ctx, eph_pub, blinding_key, nonce)) return std::nullopt;

    secp256k1_pedersen_commitment commit;
    if (secp256k1_pedersen_commitment_parse(ctx, &commit, out.nValue.vch.data()) != 1) {
        return std::nullopt;
    }

    unsigned char blind_out[32];
    uint64_t value_out = 0;
    uint64_t min_value = 0, max_value = 0;
    unsigned char message[4096];
    size_t msg_len = sizeof(message);
    if (secp256k1_rangeproof_rewind(ctx, blind_out, &value_out, message, &msg_len,
                                    nonce.data(), &min_value, &max_value, &commit,
                                    out.rangeproof.data(), out.rangeproof.size(),
                                    nullptr, 0, secp256k1_generator_h) != 1) {
        return std::nullopt;
    }
    uint256 blind;
    std::memcpy(blind.data(), blind_out, 32);
    return std::make_pair(static_cast<CAmount>(value_out), blind);
}

} // namespace blinding
