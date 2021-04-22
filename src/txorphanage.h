// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXORPHANAGE_H
#define BITCOIN_TXORPHANAGE_H

#include <net.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <sync.h>

#include <map>
#include <set>

/** A class to track orphan transactions (failed on TX_MISSING_INPUTS)
 * Since we cannot distinguish orphans from bad transactions with
 * non-existent inputs, we heavily limit the number of orphans
 * we keep and the duration we keep them for.
 */
class TxOrphanage {
public:
    /** Add a new orphan transaction */
    bool AddTx(const CTransactionRef& tx, NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Check if we already have an orphan transaction (by txid or wtxid) */
    bool HaveTx(const GenTxid& gtxid) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Get an orphan transaction for a peer to work on
     *  Returns false and sets more to false if there are no transactions
     *  to work on. Otherwise returns true, and populates its arguments with
     *  the tx and whether there are more orphans for this
     *  peer to work on after this tx.
     */
    bool GetTxToReconsider(NodeId peer, CTransactionRef& ref, bool& more) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Erase an orphan by txid */
    int EraseTx(const uint256& txid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) { LOCK(m_mutex); return _EraseTx(txid); }

    /** Erase all orphans announced by a peer (eg, after that peer disconnects) */
    void EraseForPeer(NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Erase all orphans included in or invalidated by a new block */
    void EraseForBlock(const CBlock& block) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Limit the orphanage to the given maximum */
    unsigned int LimitOrphans(unsigned int max_orphans) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Add any orphans that list a particular tx as a parent into the from peer's work set */
    void AddChildrenToWorkSet(const CTransaction& tx) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);;

protected:
    /** Guards data */
    mutable Mutex m_mutex;

    /** Erase an orphan by txid (internal, lock must already be held) */
    int _EraseTx(const uint256& txid) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    struct OrphanTx {
        CTransactionRef tx;
        NodeId fromPeer;
        int64_t nTimeExpire;
        size_t list_pos;
    };

    using OrphanMap = std::map<uint256, OrphanTx>;

    struct IteratorComparator
    {
        bool operator()(const OrphanMap::iterator& a, const OrphanMap::iterator& b) const
        {
            return &(*a) < &(*b);
        }
    };

    /** Map from txid to orphan transaction record. Limited by
     *  -maxorphantx/DEFAULT_MAX_ORPHAN_TRANSACTIONS */
    OrphanMap m_orphans GUARDED_BY(m_mutex);

    /** Which peer provided the orphans that need to be reconsidered */
    std::multimap<NodeId, uint256> m_peer_work_set GUARDED_BY(m_mutex);

    /** Index from the parents' COutPoint into the m_orphans. Used
     *  to remove orphan transactions from the m_orphans */
    std::map<COutPoint, std::set<OrphanMap::iterator, IteratorComparator>> m_outpoint_to_orphan_it GUARDED_BY(m_mutex);

    /** Orphan transactions in vector for quick random eviction */
    std::vector<OrphanMap::iterator> m_orphan_list GUARDED_BY(m_mutex);

    /** Index from wtxid into the m_orphans to lookup orphan
     *  transactions using their witness ids. */
    std::map<uint256, OrphanMap::iterator> m_wtxid_to_orphan_it GUARDED_BY(m_mutex);
};

#endif // BITCOIN_TXORPHANAGE_H
