// Copyright (c) 2014-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <deploymentstatus.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <versionbits.h>

#include <boost/test/unit_test.hpp>

using ThresholdState = ConditionLogic::State;

/* Define a virtual block time, one block per 10 minutes after Nov 14 2014, 0:55:36am */
static int32_t TestTime(int nHeight) { return 1415926536 + 600 * nHeight; }

static const std::string StateName(ThresholdState state)
{
    switch (state) {
    case ThresholdState::DEFINED:   return "DEFINED";
    case ThresholdState::STARTED:   return "STARTED";
    case ThresholdState::LOCKED_IN: return "LOCKED_IN";
    case ThresholdState::ACTIVE:    return "ACTIVE";
    case ThresholdState::FAILED:    return "FAILED";
    } // no default case, so the compiler can warn about missing cases
    return "";
}

class TestConditionLogic : public ConditionLogic
{
protected:
    Consensus::BIP9Deployment m_dep;
    ConditionLogic::Cache m_cache;

public:
    TestConditionLogic() : ConditionLogic{m_dep}
    {
        m_dep.bit = 8;
        m_dep.nStartTime = TestTime(10000);
        m_dep.nTimeout = TestTime(20000);
        m_dep.period = 1000;
        m_dep.threshold = 900;
        m_dep.min_activation_height = 0;
    }

    void clear() { ConditionLogic::ClearCache(m_cache); }
    ThresholdState GetStateFor(const CBlockIndex* pindexPrev) { return ConditionLogic::GetStateFor(m_cache, pindexPrev); }
    int GetStateSinceHeightFor(const CBlockIndex* pindexPrev) { return ConditionLogic::GetStateSinceHeightFor(m_cache, pindexPrev); }
};


class TestDelayedActivationConditionLogic : public TestConditionLogic
{
public:
    TestDelayedActivationConditionLogic() : TestConditionLogic() { m_dep.min_activation_height = 15000; }
};

class TestAlwaysActiveConditionLogic : public TestConditionLogic
{
public:
    TestAlwaysActiveConditionLogic() : TestConditionLogic() { m_dep.nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE; }
};

class TestNeverActiveConditionLogic : public TestConditionLogic
{
public:
    TestNeverActiveConditionLogic() : TestConditionLogic() { m_dep.nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE; }
};

#define CHECKERS 6

class VersionBitsTester
{
    // A fake blockchain
    std::vector<CBlockIndex*> vpblock;

    // 6 independent logics for the same bit.
    // The first one performs all checks, the second only 50%, the third only 25%, etc...
    // This is to test whether lack of cached information leads to the same results.
    TestConditionLogic logic[CHECKERS];
    // Another 6 that assume delayed activation
    TestDelayedActivationConditionLogic logic_delayed[CHECKERS];
    // Another 6 that assume always active activation
    TestAlwaysActiveConditionLogic logic_always[CHECKERS];
    // Another 6 that assume never active activation
    TestNeverActiveConditionLogic logic_never[CHECKERS];

    // Test counter (to identify failures)
    int num{1000};

public:
    VersionBitsTester& Reset() {
        // Have each group of tests be counted by the 1000s part, starting at 1000
        num = num - (num % 1000) + 1000;

        for (unsigned int i = 0; i < vpblock.size(); i++) {
            delete vpblock[i];
        }
        for (unsigned int  i = 0; i < CHECKERS; i++) {
            logic[i].clear();
            logic_delayed[i].clear();
            logic_always[i].clear();
            logic_never[i].clear();
        }
        vpblock.clear();
        return *this;
    }

    ~VersionBitsTester() {
         Reset();
    }

    VersionBitsTester& Mine(unsigned int height, int32_t nTime, int32_t nVersion) {
        while (vpblock.size() < height) {
            CBlockIndex* pindex = new CBlockIndex();
            pindex->nHeight = vpblock.size();
            pindex->pprev = Tip();
            pindex->nTime = nTime;
            pindex->nVersion = (VERSIONBITS_TOP_BITS | nVersion);
            pindex->BuildSkip();
            vpblock.push_back(pindex);
        }
        return *this;
    }

    VersionBitsTester& TestStateSinceHeight(int height)
    {
        return TestStateSinceHeight(height, height);
    }

    VersionBitsTester& TestStateSinceHeight(int height, int height_delayed)
    {
        const CBlockIndex* tip = Tip();
        for (int i = 0; i < CHECKERS; i++) {
            if (InsecureRandBits(i) == 0) {
                BOOST_CHECK_MESSAGE(logic[i].GetStateSinceHeightFor(tip) == height, strprintf("Test %i for StateSinceHeight", num));
                BOOST_CHECK_MESSAGE(logic_delayed[i].GetStateSinceHeightFor(tip) == height_delayed, strprintf("Test %i for StateSinceHeight (delayed)", num));
                BOOST_CHECK_MESSAGE(logic_always[i].GetStateSinceHeightFor(tip) == 0, strprintf("Test %i for StateSinceHeight (always active)", num));
                BOOST_CHECK_MESSAGE(logic_never[i].GetStateSinceHeightFor(tip) == 0, strprintf("Test %i for StateSinceHeight (never active)", num));
            }
        }
        num++;
        return *this;
    }

    VersionBitsTester& TestState(ThresholdState exp)
    {
        return TestState(exp, exp);
    }

    VersionBitsTester& TestState(ThresholdState exp, ThresholdState exp_delayed)
    {
        if (exp != exp_delayed) {
            // only expected differences are that delayed stays in locked_in longer
            BOOST_CHECK_EQUAL(exp, ThresholdState::ACTIVE);
            BOOST_CHECK_EQUAL(exp_delayed, ThresholdState::LOCKED_IN);
        }

        const CBlockIndex* pindex = Tip();
        for (int i = 0; i < CHECKERS; i++) {
            if (InsecureRandBits(i) == 0) {
                ThresholdState got = logic[i].GetStateFor(pindex);
                ThresholdState got_delayed = logic_delayed[i].GetStateFor(pindex);
                ThresholdState got_always = logic_always[i].GetStateFor(pindex);
                ThresholdState got_never = logic_never[i].GetStateFor(pindex);
                // nHeight of the next block. If vpblock is empty, the next (ie first)
                // block should be the genesis block with nHeight == 0.
                int height = pindex == nullptr ? 0 : pindex->nHeight + 1;
                BOOST_CHECK_MESSAGE(got == exp, strprintf("Test %i for %s height %d (got %s)", num, StateName(exp), height, StateName(got)));
                BOOST_CHECK_MESSAGE(got_delayed == exp_delayed, strprintf("Test %i for %s height %d (got %s; delayed case)", num, StateName(exp_delayed), height, StateName(got_delayed)));
                BOOST_CHECK_MESSAGE(got_always == ThresholdState::ACTIVE, strprintf("Test %i for ACTIVE height %d (got %s; always active case)", num, height, StateName(got_always)));
                BOOST_CHECK_MESSAGE(got_never == ThresholdState::FAILED, strprintf("Test %i for FAILED height %d (got %s; never active case)", num, height, StateName(got_never)));
            }
        }
        num++;
        return *this;
    }

    VersionBitsTester& TestDefined() { return TestState(ThresholdState::DEFINED); }
    VersionBitsTester& TestStarted() { return TestState(ThresholdState::STARTED); }
    VersionBitsTester& TestLockedIn() { return TestState(ThresholdState::LOCKED_IN); }
    VersionBitsTester& TestActive() { return TestState(ThresholdState::ACTIVE); }
    VersionBitsTester& TestFailed() { return TestState(ThresholdState::FAILED); }

    // non-delayed should be active; delayed should still be locked in
    VersionBitsTester& TestActiveDelayed() { return TestState(ThresholdState::ACTIVE, ThresholdState::LOCKED_IN); }

    CBlockIndex* Tip() { return vpblock.empty() ? nullptr : vpblock.back(); }
};

BOOST_FIXTURE_TEST_SUITE(versionbits_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(versionbits_test)
{
    for (int i = 0; i < 64; i++) {
        // DEFINED -> STARTED after timeout reached -> FAILED
        VersionBitsTester().TestDefined().TestStateSinceHeight(0)
                           .Mine(1, TestTime(1), 0x100).TestDefined().TestStateSinceHeight(0)
                           .Mine(11, TestTime(11), 0x100).TestDefined().TestStateSinceHeight(0)
                           .Mine(989, TestTime(989), 0x100).TestDefined().TestStateSinceHeight(0)
                           .Mine(999, TestTime(20000), 0x100).TestDefined().TestStateSinceHeight(0) // Timeout and start time reached simultaneously
                           .Mine(1000, TestTime(20000), 0).TestStarted().TestStateSinceHeight(1000) // Hit started, stop signalling
                           .Mine(1999, TestTime(30001), 0).TestStarted().TestStateSinceHeight(1000)
                           .Mine(2000, TestTime(30002), 0x100).TestFailed().TestStateSinceHeight(2000) // Hit failed, start signalling again
                           .Mine(2001, TestTime(30003), 0x100).TestFailed().TestStateSinceHeight(2000)
                           .Mine(2999, TestTime(30004), 0x100).TestFailed().TestStateSinceHeight(2000)
                           .Mine(3000, TestTime(30005), 0x100).TestFailed().TestStateSinceHeight(2000)
                           .Mine(4000, TestTime(30006), 0x100).TestFailed().TestStateSinceHeight(2000)

        // DEFINED -> STARTED -> FAILED
                           .Reset().TestDefined().TestStateSinceHeight(0)
                           .Mine(1, TestTime(1), 0).TestDefined().TestStateSinceHeight(0)
                           .Mine(1000, TestTime(10000) - 1, 0x100).TestDefined().TestStateSinceHeight(0) // One second more and it would be defined
                           .Mine(2000, TestTime(10000), 0x100).TestStarted().TestStateSinceHeight(2000) // So that's what happens the next period
                           .Mine(2051, TestTime(10010), 0).TestStarted().TestStateSinceHeight(2000) // 51 old blocks
                           .Mine(2950, TestTime(10020), 0x100).TestStarted().TestStateSinceHeight(2000) // 899 new blocks
                           .Mine(3000, TestTime(20000), 0).TestFailed().TestStateSinceHeight(3000) // 50 old blocks (so 899 out of the past 1000)
                           .Mine(4000, TestTime(20010), 0x100).TestFailed().TestStateSinceHeight(3000)

        // DEFINED -> STARTED -> LOCKEDIN after timeout reached -> ACTIVE
                           .Reset().TestDefined().TestStateSinceHeight(0)
                           .Mine(1, TestTime(1), 0).TestDefined().TestStateSinceHeight(0)
                           .Mine(1000, TestTime(10000) - 1, 0x101).TestDefined().TestStateSinceHeight(0) // One second more and it would be defined
                           .Mine(2000, TestTime(10000), 0x101).TestStarted().TestStateSinceHeight(2000) // So that's what happens the next period
                           .Mine(2999, TestTime(30000), 0x100).TestStarted().TestStateSinceHeight(2000) // 999 new blocks
                           .Mine(3000, TestTime(30000), 0x100).TestLockedIn().TestStateSinceHeight(3000) // 1 new block (so 1000 out of the past 1000 are new)
                           .Mine(3999, TestTime(30001), 0).TestLockedIn().TestStateSinceHeight(3000)
                           .Mine(4000, TestTime(30002), 0).TestActiveDelayed().TestStateSinceHeight(4000, 3000)
                           .Mine(14333, TestTime(30003), 0).TestActiveDelayed().TestStateSinceHeight(4000, 3000)
                           .Mine(24000, TestTime(40000), 0).TestActive().TestStateSinceHeight(4000, 15000)

        // DEFINED -> STARTED -> LOCKEDIN before timeout -> ACTIVE
                           .Reset().TestDefined()
                           .Mine(1, TestTime(1), 0).TestDefined().TestStateSinceHeight(0)
                           .Mine(1000, TestTime(10000) - 1, 0x101).TestDefined().TestStateSinceHeight(0) // One second more and it would be defined
                           .Mine(2000, TestTime(10000), 0x101).TestStarted().TestStateSinceHeight(2000) // So that's what happens the next period
                           .Mine(2050, TestTime(10010), 0x200).TestStarted().TestStateSinceHeight(2000) // 50 old blocks
                           .Mine(2950, TestTime(10020), 0x100).TestStarted().TestStateSinceHeight(2000) // 900 new blocks
                           .Mine(2999, TestTime(19999), 0x200).TestStarted().TestStateSinceHeight(2000) // 49 old blocks
                           .Mine(3000, TestTime(29999), 0x200).TestLockedIn().TestStateSinceHeight(3000) // 1 old block (so 900 out of the past 1000)
                           .Mine(3999, TestTime(30001), 0).TestLockedIn().TestStateSinceHeight(3000)
                           .Mine(4000, TestTime(30002), 0).TestActiveDelayed().TestStateSinceHeight(4000, 3000) // delayed will not become active until height=15000
                           .Mine(14333, TestTime(30003), 0).TestActiveDelayed().TestStateSinceHeight(4000, 3000)
                           .Mine(15000, TestTime(40000), 0).TestActive().TestStateSinceHeight(4000, 15000)
                           .Mine(24000, TestTime(40000), 0).TestActive().TestStateSinceHeight(4000, 15000)

        // DEFINED multiple periods -> STARTED multiple periods -> FAILED
                           .Reset().TestDefined().TestStateSinceHeight(0)
                           .Mine(999, TestTime(999), 0).TestDefined().TestStateSinceHeight(0)
                           .Mine(1000, TestTime(1000), 0).TestDefined().TestStateSinceHeight(0)
                           .Mine(2000, TestTime(2000), 0).TestDefined().TestStateSinceHeight(0)
                           .Mine(3000, TestTime(10000), 0).TestStarted().TestStateSinceHeight(3000)
                           .Mine(4000, TestTime(10000), 0).TestStarted().TestStateSinceHeight(3000)
                           .Mine(5000, TestTime(10000), 0).TestStarted().TestStateSinceHeight(3000)
                           .Mine(5999, TestTime(20000), 0).TestStarted().TestStateSinceHeight(3000)
                           .Mine(6000, TestTime(20000), 0).TestFailed().TestStateSinceHeight(6000)
                           .Mine(7000, TestTime(20000), 0x100).TestFailed().TestStateSinceHeight(6000)
                           .Mine(24000, TestTime(20000), 0x100).TestFailed().TestStateSinceHeight(6000) // stay in FAILED no matter how much we signal
        ;
    }
}

/** Check that ComputeBlockVersion will set the appropriate bit correctly */
static void check_computeblockversion(VersionBitsCache& versionbitscache, const Consensus::Params& params, const ConditionLogic& logic)
{
    // Clear the cache everytime
    versionbitscache.Clear();

    const auto& dep = logic.Dep();
    const int64_t bit = dep.bit;
    const int64_t nStartTime = dep.nStartTime;
    const int64_t nTimeout = dep.nTimeout;
    const int min_activation_height = dep.min_activation_height;

    BOOST_CHECK_EQUAL(dep.period, params.nMinerConfirmationWindow);
    BOOST_CHECK_EQUAL(dep.threshold, params.nRuleChangeActivationThreshold);

    // test will not function correctly if period or threshold are misspecified
    BOOST_REQUIRE(dep.period > 0);
    BOOST_REQUIRE(dep.threshold >= 0);
    BOOST_REQUIRE(dep.threshold <= dep.period);

    const uint32_t period = dep.period;

    // should not be any signalling for first block
    BOOST_CHECK_EQUAL(versionbitscache.ComputeBlockVersion(nullptr, params), VERSIONBITS_TOP_BITS);

    // always/never active deployments shouldn't need to be tested further
    if (nStartTime == Consensus::BIP9Deployment::ALWAYS_ACTIVE ||
        nStartTime == Consensus::BIP9Deployment::NEVER_ACTIVE)
    {
        BOOST_CHECK_EQUAL(min_activation_height, 0);
        BOOST_CHECK_EQUAL(nTimeout, Consensus::BIP9Deployment::NO_TIMEOUT);
        return;
    }

    BOOST_REQUIRE(nStartTime < nTimeout);
    BOOST_REQUIRE(nStartTime >= 0);
    BOOST_REQUIRE(nTimeout <= std::numeric_limits<uint32_t>::max() || nTimeout == Consensus::BIP9Deployment::NO_TIMEOUT);
    BOOST_REQUIRE(0 <= bit && bit < 32);
    // Make sure that no deployment tries to set an invalid bit.
    BOOST_REQUIRE(((1 << bit) & VERSIONBITS_TOP_MASK) == 0);
    BOOST_REQUIRE(min_activation_height >= 0);
    // Check min_activation_height is on a retarget boundary
    BOOST_REQUIRE_EQUAL(min_activation_height % period, 0U);

    const uint32_t bitmask{logic.Mask()};
    BOOST_CHECK_EQUAL(bitmask, uint32_t{1} << bit);

    // In the first chain, test that the bit is set by CBV until it has failed.
    // In the second chain, test the bit is set by CBV while STARTED and
    // LOCKED-IN, and then no longer set while ACTIVE.
    VersionBitsTester firstChain, secondChain;

    int64_t nTime = nStartTime;

    const CBlockIndex *lastBlock = nullptr;

    // Before MedianTimePast of the chain has crossed nStartTime, the bit
    // should not be set.
    if (nTime == 0) {
        // since CBlockIndex::nTime is uint32_t we can't represent any
        // earlier time, so will transition from DEFINED to STARTED at the
        // end of the first period by mining blocks at nTime == 0
        lastBlock = firstChain.Mine(period - 1, nTime, 0).Tip();
        BOOST_CHECK_EQUAL(versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit), 0);
        lastBlock = firstChain.Mine(period, nTime, 0).Tip();
        BOOST_CHECK((versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit)) != 0);
        // then we'll keep mining at nStartTime...
    } else {
        // use a time 1s earlier than start time to check we stay DEFINED
        --nTime;

        // Start generating blocks before nStartTime
        lastBlock = firstChain.Mine(period, nTime, 0).Tip();
        BOOST_CHECK_EQUAL(versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit), 0);

        // Mine more blocks (4 less than the adjustment period) at the old time, and check that CBV isn't setting the bit yet.
        for (uint32_t i = 1; i < period - 4; i++) {
            lastBlock = firstChain.Mine(period + i, nTime, 0).Tip();
            BOOST_CHECK_EQUAL(versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit), 0);
        }
        // Now mine 5 more blocks at the start time -- MTP should not have passed yet, so
        // CBV should still not yet set the bit.
        nTime = nStartTime;
        for (uint32_t i = period - 4; i <= period; i++) {
            lastBlock = firstChain.Mine(period + i, nTime, 0).Tip();
            BOOST_CHECK_EQUAL(versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit), 0);
        }
        // Next we will advance to the next period and transition to STARTED,
    }

    lastBlock = firstChain.Mine(period * 3, nTime, 0).Tip();
    // so ComputeBlockVersion should now set the bit,
    BOOST_CHECK((versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit)) != 0);
    // and should also be using the VERSIONBITS_TOP_BITS.
    BOOST_CHECK_EQUAL(versionbitscache.ComputeBlockVersion(lastBlock, params) & VERSIONBITS_TOP_MASK, VERSIONBITS_TOP_BITS);

    // Check that ComputeBlockVersion will set the bit until nTimeout
    nTime += 600;
    uint32_t blocksToMine = period * 2; // test blocks for up to 2 time periods
    uint32_t nHeight = period * 3;
    // These blocks are all before nTimeout is reached.
    while (nTime < nTimeout && blocksToMine > 0) {
        lastBlock = firstChain.Mine(nHeight+1, nTime, 0).Tip();
        BOOST_CHECK((versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit)) != 0);
        BOOST_CHECK_EQUAL(versionbitscache.ComputeBlockVersion(lastBlock, params) & VERSIONBITS_TOP_MASK, VERSIONBITS_TOP_BITS);
        blocksToMine--;
        nTime += 600;
        nHeight += 1;
    }

    if (nTimeout != Consensus::BIP9Deployment::NO_TIMEOUT) {
        // can reach any nTimeout other than NO_TIMEOUT due to earlier BOOST_REQUIRE

        nTime = nTimeout;

        // finish the last period before we start timing out
        while (nHeight % period != 0) {
            lastBlock = firstChain.Mine(nHeight+1, nTime - 1, 0).Tip();
            BOOST_CHECK((versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit)) != 0);
            nHeight += 1;
        }

        // FAILED is only triggered at the end of a period, so CBV should be setting
        // the bit until the period transition.
        for (uint32_t i = 0; i < period - 1; i++) {
            lastBlock = firstChain.Mine(nHeight+1, nTime, 0).Tip();
            BOOST_CHECK((versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit)) != 0);
            nHeight += 1;
        }
        // The next block should trigger no longer setting the bit.
        lastBlock = firstChain.Mine(nHeight+1, nTime, 0).Tip();
        BOOST_CHECK_EQUAL(versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit), 0);
    }

    // On a new chain:
    // verify that the bit will be set after lock-in, and then stop being set
    // after activation.
    nTime = nStartTime;

    // Mine one period worth of blocks, and check that the bit will be on for the
    // next period.
    lastBlock = secondChain.Mine(period, nTime, 0).Tip();
    BOOST_CHECK((versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit)) != 0);

    // Mine another period worth of blocks, signaling the new bit.
    lastBlock = secondChain.Mine(period * 2, nTime, VERSIONBITS_TOP_BITS | (1<<bit)).Tip();
    // After one period of setting the bit on each block, it should have locked in.
    // We keep setting the bit for one more period though, until activation.
    BOOST_CHECK((versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit)) != 0);

    // Now check that we keep mining the block until the end of this period, and
    // then stop at the beginning of the next period.
    lastBlock = secondChain.Mine((period * 3) - 1, nTime, 0).Tip();
    BOOST_CHECK((versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit)) != 0);
    lastBlock = secondChain.Mine(period * 3, nTime, 0).Tip();

    if (lastBlock->nHeight + 1 < min_activation_height) {
        // check signalling continues while min_activation_height is not reached
        lastBlock = secondChain.Mine(min_activation_height - 1, nTime, 0).Tip();
        BOOST_CHECK((versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit)) != 0);
        // then reach min_activation_height, which was already REQUIRE'd to start a new period
        lastBlock = secondChain.Mine(min_activation_height, nTime, 0).Tip();
    }

    // Check that we don't signal after activation
    BOOST_CHECK_EQUAL(versionbitscache.ComputeBlockVersion(lastBlock, params) & (1 << bit), 0);
}

static void check_computeblockversion(VersionBitsCache& versionbitscache, const Consensus::Params& params, const Consensus::BIP9Deployment& dep)
{
    check_computeblockversion(versionbitscache, params, ConditionLogic(dep));
}

BOOST_AUTO_TEST_CASE(versionbits_computeblockversion)
{
    VersionBitsCache vbcache; // don't use chainman versionbitscache since we want custom chain params

    // check that any deployment on any chain can conceivably reach both
    // ACTIVE and FAILED states in roughly the way we expect
    for (const auto& chain_name : {CBaseChainParams::MAIN, CBaseChainParams::TESTNET, CBaseChainParams::SIGNET, CBaseChainParams::REGTEST}) {
        const auto chainParams = CreateChainParams(*m_node.args, chain_name);
        uint32_t chain_all_vbits{0};
        vbcache.ForEachDeployment_nocache(chainParams->GetConsensus(), [&](auto pos, const auto& logic) {
            // Check that no bits are re-used (within the same chain). This is
            // disallowed because the transition to FAILED (on timeout) does
            // not take precedence over STARTED/LOCKED_IN. So all softforks on
            // the same bit might overlap, even when non-overlapping start-end
            // times are picked.
            const uint32_t dep_mask{logic.Mask()};
            BOOST_CHECK(!(chain_all_vbits & dep_mask));
            chain_all_vbits |= dep_mask;

            check_computeblockversion(vbcache, chainParams->GetConsensus(), logic);
        });
    }

    {
        // Use regtest/testdummy to ensure we always exercise some
        // deployment that's not always/never active
        ArgsManager args;
        args.ForceSetArg("-vbparams", "testdummy:1199145601:1230767999"); // January 1, 2008 - December 31, 2008
        const auto chainParams = CreateChainParams(args, CBaseChainParams::REGTEST);
        check_computeblockversion(vbcache, chainParams->GetConsensus(), std::get<Consensus::DEPLOYMENT_TESTDUMMY>(chainParams->GetConsensus().vDeployments));
    }

    {
        // Use regtest/testdummy to ensure we always exercise the
        // min_activation_height test, even if we're not using that in a
        // live deployment
        ArgsManager args;
        args.ForceSetArg("-vbparams", "testdummy:1199145601:1230767999:403200"); // January 1, 2008 - December 31, 2008, min act height 403200
        const auto chainParams = CreateChainParams(args, CBaseChainParams::REGTEST);
        check_computeblockversion(vbcache, chainParams->GetConsensus(), std::get<Consensus::DEPLOYMENT_TESTDUMMY>(chainParams->GetConsensus().vDeployments));
    }
}

BOOST_AUTO_TEST_SUITE_END()
