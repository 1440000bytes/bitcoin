// Copyright (c) 2019-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SIGNET_H
#define BITCOIN_SIGNET_H

#include <consensus/params.h>
#include <primitives/transaction.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cstdint>
#include <vector>
#include <array>

#include <span.h>

/**
 * Extract signature and check whether a block has a valid solution
 */
bool CheckBlockSolution(const CBlock& block, const Consensus::Params& consensusParams);

/**
 * Generate the signet tx corresponding to the given block
 *
 * The signet tx commits to everything in the block except:
 * 1. It hashes a modified merkle root with the signet signature removed.
 * 2. It skips the nonce.
 */
uint256 GetSignetHash(const CBlock& block);

/**
 * Attempt to get the data for the section with the given header in the witness commitment of the block.
 *
 * Returns false if header was not found. The data (excluding the 4 byte header) is written into result if found.
 */
bool GetWitnessCommitmentSection(const CBlock& block, Span<const uint8_t> header, std::vector<uint8_t>& result);

/**
 * Attempt to add or update the data for the section with the given header in the witness commitment of the block.
 *
 * This operation may fail and return false, if no witness commitment exists upon call time. Returns true on success.
 */
bool SetWitnessCommitmentSection(CBlock& block, Span<const uint8_t> header, const std::vector<uint8_t>& data);
bool SetWitnessCommitmentSection(CMutableTransaction& tx, Span<const uint8_t> header, const std::vector<uint8_t>& data);

/**
 * The tx based equivalent of the above.
 */
CTransaction SignetTx(const CBlock& block, const std::vector<std::vector<uint8_t>>& witness_prefix);

#endif // BITCOIN_SIGNET_H
