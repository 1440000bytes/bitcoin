// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Confidential Transactions primitives (Phase 2a).
//
// A confidential output replaces the explicit int64 amount with either an
// explicit value (backward-compatible) or a 33-byte Pedersen commitment
// C = v*H + r*G, accompanied by an ephemeral-pubkey nonce used to ECDH the
// blinding secret to the receiver. The wire format (prefix byte + payload)
// mirrors Elements so tooling and reasoning carry over. Asset blinding is
// intentionally omitted: this is BTC-only single-asset CT.

#ifndef BITCOIN_PRIMITIVES_CONFIDENTIAL_H
#define BITCOIN_PRIMITIVES_CONFIDENTIAL_H

#include <consensus/amount.h>
#include <serialize.h>
#include <span.h>

#include <cassert>
#include <cstdint>
#include <vector>

/**
 * A confidential value: either explicit (prefix 0x01, 8-byte big-endian amount)
 * or a Pedersen commitment (prefix 0x08/0x09, 32-byte compressed point). A null
 * value (prefix 0x00) carries no payload.
 *
 * vch[0] is always the prefix byte; the remaining bytes are the payload.
 */
class CConfidentialValue
{
public:
    static constexpr unsigned char PREFIX_NULL = 0;
    static constexpr unsigned char PREFIX_EXPLICIT = 1;
    static constexpr unsigned char PREFIX_COMMIT_EVEN = 8;
    static constexpr unsigned char PREFIX_COMMIT_ODD = 9;

    static constexpr size_t EXPLICIT_SIZE = 9;    //!< 1 prefix + 8 amount
    static constexpr size_t COMMITMENT_SIZE = 33; //!< 1 prefix + 32 point

    std::vector<unsigned char> vch;

    CConfidentialValue() { SetNull(); }
    explicit CConfidentialValue(CAmount amount) { SetToAmount(amount); }

    void SetNull() { vch.clear(); }
    bool IsNull() const { return vch.empty(); }

    bool IsExplicit() const { return vch.size() == EXPLICIT_SIZE && vch[0] == PREFIX_EXPLICIT; }
    bool IsCommitment() const
    {
        return vch.size() == COMMITMENT_SIZE && (vch[0] == PREFIX_COMMIT_EVEN || vch[0] == PREFIX_COMMIT_ODD);
    }
    bool IsValid() const { return IsNull() || IsExplicit() || IsCommitment(); }

    void SetToAmount(CAmount amount)
    {
        vch.resize(EXPLICIT_SIZE);
        vch[0] = PREFIX_EXPLICIT;
        const uint64_t v = static_cast<uint64_t>(amount);
        for (int i = 0; i < 8; ++i) {
            vch[1 + i] = static_cast<unsigned char>((v >> (8 * (7 - i))) & 0xff); // big-endian
        }
    }

    //! Only valid for an explicit value; commitments hide the amount.
    CAmount GetAmount() const
    {
        assert(IsExplicit());
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v = (v << 8) | vch[1 + i];
        }
        return static_cast<CAmount>(v);
    }

    //! Install a 33-byte commitment as produced by secp256k1_pedersen_commitment_serialize.
    void SetToCommitment(Span<const unsigned char> commitment33)
    {
        assert(commitment33.size() == COMMITMENT_SIZE);
        vch.assign(commitment33.begin(), commitment33.end());
        assert(vch[0] == PREFIX_COMMIT_EVEN || vch[0] == PREFIX_COMMIT_ODD);
    }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        const unsigned char prefix = vch.empty() ? PREFIX_NULL : vch[0];
        ::Serialize(s, prefix);
        switch (prefix) {
        case PREFIX_NULL:
            break;
        case PREFIX_EXPLICIT:
            s.write(MakeByteSpan(vch).subspan(1, 8));
            break;
        case PREFIX_COMMIT_EVEN:
        case PREFIX_COMMIT_ODD:
            s.write(MakeByteSpan(vch).subspan(1, 32));
            break;
        default:
            throw std::ios_base::failure("CConfidentialValue: unknown prefix");
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        unsigned char prefix;
        ::Unserialize(s, prefix);
        switch (prefix) {
        case PREFIX_NULL:
            vch.clear();
            break;
        case PREFIX_EXPLICIT:
            vch.resize(EXPLICIT_SIZE);
            vch[0] = prefix;
            s.read(MakeWritableByteSpan(vch).subspan(1, 8));
            break;
        case PREFIX_COMMIT_EVEN:
        case PREFIX_COMMIT_ODD:
            vch.resize(COMMITMENT_SIZE);
            vch[0] = prefix;
            s.read(MakeWritableByteSpan(vch).subspan(1, 32));
            break;
        default:
            throw std::ios_base::failure("CConfidentialValue: unknown prefix");
        }
    }

    friend bool operator==(const CConfidentialValue& a, const CConfidentialValue& b) { return a.vch == b.vch; }
    friend bool operator!=(const CConfidentialValue& a, const CConfidentialValue& b) { return a.vch != b.vch; }
};

/**
 * A confidential nonce: null (prefix 0x00) or a 33-byte ephemeral pubkey
 * (prefix 0x02/0x03) that the sender places in the output so the receiver can
 * ECDH-derive the blinding secret. Stored identically to a commitment payload.
 */
class CConfidentialNonce
{
public:
    static constexpr size_t COMMITMENT_SIZE = 33;

    std::vector<unsigned char> vch;

    CConfidentialNonce() { SetNull(); }

    void SetNull() { vch.clear(); }
    bool IsNull() const { return vch.empty(); }
    bool IsCommitment() const
    {
        return vch.size() == COMMITMENT_SIZE && (vch[0] == 2 || vch[0] == 3);
    }
    bool IsValid() const { return IsNull() || IsCommitment(); }

    void SetToPubKey(Span<const unsigned char> pubkey33)
    {
        assert(pubkey33.size() == COMMITMENT_SIZE);
        vch.assign(pubkey33.begin(), pubkey33.end());
    }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        const unsigned char prefix = vch.empty() ? 0 : vch[0];
        ::Serialize(s, prefix);
        if (prefix != 0) {
            s.write(MakeByteSpan(vch).subspan(1, 32));
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        unsigned char prefix;
        ::Unserialize(s, prefix);
        if (prefix == 0) {
            vch.clear();
        } else {
            vch.resize(COMMITMENT_SIZE);
            vch[0] = prefix;
            s.read(MakeWritableByteSpan(vch).subspan(1, 32));
        }
    }

    friend bool operator==(const CConfidentialNonce& a, const CConfidentialNonce& b) { return a.vch == b.vch; }
    friend bool operator!=(const CConfidentialNonce& a, const CConfidentialNonce& b) { return a.vch != b.vch; }
};

#endif // BITCOIN_PRIMITIVES_CONFIDENTIAL_H
