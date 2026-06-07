// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Consensus verification for Confidential Transactions (Phase 3).
//
// A confidential transaction hides output amounts behind Pedersen commitments.
// Because the verifier cannot see the amounts, the classic "sum(inputs) -
// sum(outputs) == fee" arithmetic is replaced by:
//
//   1. a homomorphic balance check on the commitments:
//        sum(input commitments) == sum(output commitments)
//      where every explicit value v (input or output, including the explicit
//      fee output) is folded in as a zero-blind commitment v*H; and
//   2. a range proof on every committed output, proving 0 <= v < 2^64 so a
//      forged "negative" amount cannot wrap the curve order and inflate supply.
//
// Confidentiality is per-output and optional (as in Elements/Liquid): explicit
// and committed outputs coexist, and the fee is always an explicit output.

#ifndef BITCOIN_CONSENSUS_CONFIDENTIAL_H
#define BITCOIN_CONSENSUS_CONFIDENTIAL_H

#include <primitives/confidential.h>

#include <cstdint>
#include <span>
#include <vector>

class CTxOut;

namespace ct {

/**
 * Verify the homomorphic value balance of a confidential transaction.
 *
 * Each entry is a CConfidentialValue that is either explicit (folded in as a
 * zero-blind commitment v*H) or already a Pedersen commitment. Returns true iff
 * the input commitments tally exactly against the output commitments. A null or
 * malformed value makes the check fail closed.
 */
bool VerifyValueBalance(std::span<const CConfidentialValue> inputs,
                        std::span<const CConfidentialValue> outputs);

/**
 * Verify a single output's range proof against its value commitment. The
 * commitment must be a real Pedersen commitment (not explicit). Returns true iff
 * the proof verifies for some value in [0, 2^64).
 */
bool VerifyRangeProof(const CConfidentialValue& commitment,
                      std::span<const unsigned char> rangeproof);

/**
 * Full per-transaction confidential check: every committed output must carry a
 * valid range proof, and the input/output commitments must balance. `inputs`
 * are the spent outputs (from the UTXO set), `outputs` are tx.vout. Returns true
 * iff the transaction conserves value without revealing it.
 */
bool CheckConfidential(std::span<const CTxOut> inputs,
                       std::span<const CTxOut> outputs);

} // namespace ct

#endif // BITCOIN_CONSENSUS_CONFIDENTIAL_H
