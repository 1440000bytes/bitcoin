// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Confidential Transactions blinding/unblinding (Phase 6).
//
// Sender side: turn explicit-valued outputs into Pedersen commitments, choosing
// the blinding factors so the whole transaction balances (the last blinded
// output's blind is solved), and attach to each a range proof plus an ECDH nonce
// (an ephemeral pubkey) so the receiver can recover the amount.
//
// Receiver side: ECDH the output's nonce against the receiver's blinding key to
// reconstruct the proof nonce, then rewind the range proof to recover the hidden
// value and its blinding factor.

#ifndef BITCOIN_BLIND_H
#define BITCOIN_BLIND_H

#include <consensus/amount.h>
#include <key.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <uint256.h>

#include <cstddef>
#include <optional>
#include <utility>
#include <vector>

namespace blinding {

/**
 * Blind the outputs of `tx` at the indices in `outputs_to_blind`, each paired
 * (by position) with the receiver's blinding pubkey in `receiver_blind_pubkeys`.
 *
 * `input_amounts`/`input_blinds` describe the coins being spent: an explicit
 * (unblinded) input uses blind == uint256::ZERO. Outputs not listed (e.g. the
 * explicit fee output) stay explicit and contribute a zero blind to the balance.
 *
 * On success the listed outputs carry a value commitment, an ECDH nonce, and a
 * range proof, and the transaction's commitments tally exactly. Requires at
 * least one output to blind. Returns false on any failure.
 */
bool BlindTransaction(const std::vector<CAmount>& input_amounts,
                      const std::vector<uint256>& input_blinds,
                      CMutableTransaction& tx,
                      const std::vector<size_t>& outputs_to_blind,
                      const std::vector<CPubKey>& receiver_blind_pubkeys);

/**
 * Recover (value, blinding factor) from a confidential output using the
 * receiver's blinding private key. Returns std::nullopt if the output is not
 * confidential or the key does not unblind it.
 */
std::optional<std::pair<CAmount, uint256>> UnblindOutput(const CTxOut& out, const CKey& blinding_key);

} // namespace blinding

#endif // BITCOIN_BLIND_H
