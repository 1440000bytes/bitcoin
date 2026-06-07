# Confidential Transactions on Bitcoin Core (regtest)

This branch (`ct-regtest`, forked from Bitcoin Knots `29.x-knots`) adds **single-asset
Confidential Transactions** — hidden output *amounts* via Pedersen commitments and
range proofs, ported from the design used by Elements/Liquid. Confidentiality is
**per-output and optional**: explicit and blinded outputs coexist in the same
transaction and chain, exactly as in Elements, and the fee is always explicit.

> ⚠️ This is a **proof of concept on regtest**, not production software. CT touches
> consensus-critical, inflation-sensitive code. Do not point it at real money.
> Because the output serialization changed, this is a **separate network** (the
> regtest genesis is recomputed); it is not compatible with Bitcoin mainnet.

## What was implemented

| Area | Change |
|---|---|
| Crypto | `src/secp256k1` subtree replaced with **secp256k1-zkp** (rangeproof, generator, ecdh modules) |
| Output format | `CTxOut` carries a `CConfidentialValue` (explicit *or* 33-byte commitment) + ECDH `nNonce`; range proof stored as output witness (tx witness flag bit 2), excluded from the txid |
| Consensus | `ct::CheckConfidential` — homomorphic commitment tally + a range proof on every committed output — replaces the value arithmetic in `CheckTxInputs`; `CheckTransaction`/`GetValueOut` skip committed outputs; fee = explicit empty-script output |
| UTXO | confidential-aware compressor keeps commitments in the coin set |
| Wallet crypto | `src/blind.{h,cpp}` — blind (solve blinds, ECDH-to-receiver, range-proof sign) and unblind (ECDH + range-proof rewind) |
| RPC | `blindrawtransaction`, `unblindrawtransaction` |

All of the above is covered by `test/confidential_tests.cpp` (9 unit tests:
commitments, range proofs, the balance tally, serialization, UTXO round-trip,
sighash binding, and a full blind→consensus→unblind wallet round trip).

## Build

```sh
cmake -B build -DBUILD_TESTS=ON -DENABLE_WALLET=ON -DWITH_SQLITE=ON -DRDTS_CONSENT=IMPLICIT
cmake --build build -j$(nproc) --target bitcoind bitcoin-cli test_bitcoin
build/bin/test_bitcoin --run_test=confidential_tests   # all green
```

## Try it on regtest

The amounts in a confidential transaction are hidden, so the wallet's normal
`sendtoaddress` is not wired to blind automatically; you build the tx with raw-tx
RPCs and blind it explicitly. The receiver's *blinding* key is independent of the
spending key — generate a secp256k1 keypair and use the pubkey to blind, the
privkey to unblind. See `contrib/ct-demo.py` (the script used to validate this) for
a complete, runnable example. The flow:

```
# 1. fund a raw tx (explicit inputs, ordinary payment outputs)
raw=$(bitcoin-cli -regtest createrawtransaction \
        '[{"txid":"<coinbase_txid>","vout":0}]' '[{"<addr1>":30},{"<addr2>":19.9999}]')

# 2. blind outputs 0 and 1 to the receivers' blinding pubkeys, append a 0.0001 fee
blinded=$(bitcoin-cli -regtest blindrawtransaction "$raw" '[50.0]' \
        '[{"vout":0,"pubkey":"<pub1>"},{"vout":1,"pubkey":"<pub2>"}]' 0.0001)

# 3. sign the explicit input, then submit — the node validates the commitment
#    balance + range proofs and accepts it
signed=$(bitcoin-cli -regtest signrawtransactionwithwallet "$blinded" | jq -r .hex)
bitcoin-cli -regtest sendrawtransaction "$signed"

# 4. on-chain the amounts are hidden; the receiver reveals theirs:
bitcoin-cli -regtest unblindrawtransaction "$signed" 0 "<privkey1>"   # -> amount 30
```

A confirmed run shows `getrawtransaction ... true` reporting the blinded outputs
with no readable `value`, the explicit fee output, and `unblindrawtransaction`
recovering each receiver's exact amount (and failing with the wrong key).

## Known limitations (PoC scope)

- **No asset blinding** (surjection proofs) — BTC only, single asset.
- **Spend confidential inputs via taproot**: the BIP341 sighash already commits to
  the spent commitment; segwit-v0's amount commitment was not reworked.
- The wallet does not auto-blind in `sendtoaddress`, auto-select confidential
  coins, or persist recovered blinding factors; blinding is driven via the RPCs.
- Standardness/dust policy is relaxed (`-acceptnonstdtxn=1`) for the empty-script
  fee output rather than taught about it.
