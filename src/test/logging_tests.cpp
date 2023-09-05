// Copyright (c) 2019-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <init/common.h>
#include <logging.h>
#include <logging/timer.h>
#include <test/util/setup_common.h>
#include <util/string.h>

#include <chrono>
#include <fstream>
#include <iostream>
#include <unordered_map>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(logging_tests, BasicTestingSetup)

static void ResetLogger()
{
    LogInstance().ResetLogLevels(0,0);
}

struct LogSetup : public BasicTestingSetup {
    fs::path prev_log_path;
    fs::path tmp_log_path;
    bool prev_reopen_file;
    bool prev_print_to_file;
    bool prev_log_timestamps;
    bool prev_log_threadnames;
    bool prev_log_sourcelocations;
    uint32_t prev_category_mask;
    uint32_t prev_category_trace_mask;

    LogSetup() : prev_log_path{LogInstance().m_file_path},
                 tmp_log_path{m_args.GetDataDirBase() / "tmp_debug.log"},
                 prev_reopen_file{LogInstance().m_reopen_file},
                 prev_print_to_file{LogInstance().m_print_to_file},
                 prev_log_timestamps{LogInstance().m_log_timestamps},
                 prev_log_threadnames{LogInstance().m_log_threadnames},
                 prev_log_sourcelocations{LogInstance().m_log_sourcelocations},
                 prev_category_mask{LogInstance().GetCategoryMask()},
                 prev_category_trace_mask{LogInstance().GetCategoryTraceMask()}
    {
        LogInstance().m_file_path = tmp_log_path;
        LogInstance().m_reopen_file = true;
        LogInstance().m_print_to_file = true;
        LogInstance().m_log_timestamps = false;
        LogInstance().m_log_threadnames = false;

        // Prevent tests from failing when the line number of the logs changes.
        LogInstance().m_log_sourcelocations = false;

        ResetLogger();
    }

    ~LogSetup()
    {
        LogInstance().m_file_path = prev_log_path;
        LogPrintf("Sentinel log to reopen log file\n");
        LogInstance().m_print_to_file = prev_print_to_file;
        LogInstance().m_reopen_file = prev_reopen_file;
        LogInstance().m_log_timestamps = prev_log_timestamps;
        LogInstance().m_log_threadnames = prev_log_threadnames;
        LogInstance().m_log_sourcelocations = prev_log_sourcelocations;
        LogInstance().ResetLogLevels(prev_category_mask, prev_category_trace_mask);
    }
};

BOOST_AUTO_TEST_CASE(logging_timer)
{
    auto micro_timer = BCLog::Timer<std::chrono::microseconds>("tests", "end_msg");
    const std::string_view result_prefix{"tests: msg ("};
    BOOST_CHECK_EQUAL(micro_timer.LogMsg("msg").substr(0, result_prefix.size()), result_prefix);
}

BOOST_FIXTURE_TEST_CASE(logging_LogPrintf_, LogSetup)
{
    LogInstance().m_log_sourcelocations = true;
    LogPrintf_("fn1", "src1", 1, BCLog::NET, BCLog::Level::Debug, "foo1: %s\n", "bar1");
    LogPrintf_("fn2", "src2", 2, BCLog::NET, BCLog::Level::Info, "foo2: %s\n", "bar2");
    LogPrintf_("fn3", "src3", 3, BCLog::NONE, BCLog::Level::Debug, "foo3: %s\n", "bar3");
    LogPrintf_("fn4", "src4", 4, BCLog::NONE, BCLog::Level::Info, "foo4: %s\n", "bar4");
    std::ifstream file{tmp_log_path};
    std::vector<std::string> log_lines;
    for (std::string log; std::getline(file, log);) {
        log_lines.push_back(log);
    }
    std::vector<std::string> expected = {
        "[src1:1] [fn1] [net] foo1: bar1",
        "[src2:2] [fn2] [net:info] foo2: bar2",
        "[src3:3] [fn3] [debug] foo3: bar3",
        "[src4:4] [fn4] foo4: bar4",
    };
    BOOST_CHECK_EQUAL_COLLECTIONS(log_lines.begin(), log_lines.end(), expected.begin(), expected.end());
}

BOOST_FIXTURE_TEST_CASE(logging_LogPrintMacrosDeprecated, LogSetup)
{
    LogInstance().EnableCategory(BCLog::LogFlags::ALL);

    LogPrintf("foo5: %s\n", "bar5");
    LogPrint(BCLog::NET, "foo6: %s\n", "bar6");
    LogPrintLevel(BCLog::NET, BCLog::Level::Trace, "foo4: %s\n", "bar4"); // not logged
    LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "foo7: %s\n", "bar7");
    LogPrintLevel(BCLog::NET, BCLog::Level::Info, "foo8: %s\n", "bar8");
    LogPrintLevel(BCLog::NET, BCLog::Level::Warning, "foo9: %s\n", "bar9");
    LogPrintLevel(BCLog::NET, BCLog::Level::Error, "foo10: %s\n", "bar10");
    LogPrintfCategory(BCLog::VALIDATION, "foo11: %s\n", "bar11");
    LogPrintfCategory(BCLog::ALL, "foo12: %s\n", "bar12");
    LogPrintfCategory(BCLog::NONE, "foo13: %s\n", "bar13");
    std::ifstream file{tmp_log_path};
    std::vector<std::string> log_lines;
    for (std::string log; std::getline(file, log);) {
        log_lines.push_back(log);
    }
    std::vector<std::string> expected = {
        "foo5: bar5",
        "[net] foo6: bar6",
        "[net] foo7: bar7",
        "[net:info] foo8: bar8",
        "[net:warning] foo9: bar9",
        "[net:error] foo10: bar10",
        "[validation:info] foo11: bar11",
        "[all:info] foo12: bar12",
        "foo13: bar13",
    };
    BOOST_CHECK_EQUAL_COLLECTIONS(log_lines.begin(), log_lines.end(), expected.begin(), expected.end());
}

BOOST_FIXTURE_TEST_CASE(logging_LogPrintMacros, LogSetup)
{
    LogInstance().EnableCategory(BCLog::LogFlags::ALL);

    LogTrace(BCLog::NET, "foo6: %s\n", "bar6"); // not logged
    LogDebug(BCLog::NET, "foo7: %s\n", "bar7");
    LogInfo("foo8: %s\n", "bar8");
    LogWarning("foo9: %s\n", "bar9");
    LogError("foo10: %s\n", "bar10");
    std::ifstream file{tmp_log_path};
    std::vector<std::string> log_lines;
    for (std::string log; std::getline(file, log);) {
        log_lines.push_back(log);
    }
    std::vector<std::string> expected = {
        "[net] foo7: bar7",
        "foo8: bar8",
        "[warning] foo9: bar9",
        "[error] foo10: bar10",
    };
    BOOST_CHECK_EQUAL_COLLECTIONS(log_lines.begin(), log_lines.end(), expected.begin(), expected.end());
}

BOOST_FIXTURE_TEST_CASE(logging_LogPrintMacros_CategoryName, LogSetup)
{
    LogInstance().EnableCategory(BCLog::LogFlags::ALL);
    const auto concatenated_category_names = LogInstance().LogCategoriesString();
    std::vector<std::pair<BCLog::LogFlags, std::string>> expected_category_names;
    const auto category_names = SplitString(concatenated_category_names, ',');
    for (const auto& category_name : category_names) {
        BCLog::LogFlags category;
        const auto trimmed_category_name = TrimString(category_name);
        BOOST_REQUIRE(BCLog::Logger::GetLogCategory(category, trimmed_category_name));
        expected_category_names.emplace_back(category, trimmed_category_name);
    }

    std::vector<std::string> expected;
    for (const auto& [category, name] : expected_category_names) {
        LogPrint(category, "foo: %s\n", "bar");
        std::string expected_log = "[";
        expected_log += name;
        expected_log += "] foo: bar";
        expected.push_back(expected_log);
    }

    std::ifstream file{tmp_log_path};
    std::vector<std::string> log_lines;
    for (std::string log; std::getline(file, log);) {
        log_lines.push_back(log);
    }
    BOOST_CHECK_EQUAL_COLLECTIONS(log_lines.begin(), log_lines.end(), expected.begin(), expected.end());
}

BOOST_FIXTURE_TEST_CASE(logging_SeverityLevels, LogSetup)
{
    LogInstance().EnableCategory(BCLog::LogFlags::ALL);

    LogInstance().SetCategoryLogLevel(/*category_str=*/"net", /*level_str=*/"info");

    // Global log level
    LogPrintLevel(BCLog::HTTP, BCLog::Level::Info, "foo1: %s\n", "bar1");
    LogPrintLevel(BCLog::MEMPOOL, BCLog::Level::Trace, "foo2: %s. This log level is lower than the global one.\n", "bar2");
    LogPrintLevel(BCLog::VALIDATION, BCLog::Level::Warning, "foo3: %s\n", "bar3");
    LogPrintLevel(BCLog::RPC, BCLog::Level::Error, "foo4: %s\n", "bar4");

    // Category-specific log level
    LogPrintLevel(BCLog::NET, BCLog::Level::Warning, "foo5: %s\n", "bar5");
    LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "foo6: %s. This log level is the same as the global one but lower than the category-specific one, which takes precedence. \n", "bar6");
    LogPrintLevel(BCLog::NET, BCLog::Level::Error, "foo7: %s\n", "bar7");
    LogPrintLevel(BCLog::ALL, BCLog::Level::Info, "foo8: %s\n", "bar8");
    LogPrintLevel(BCLog::NONE, BCLog::Level::Info, "foo9: %s\n", "bar9"); // no-op
    LogPrintLevel(BCLog::NONE, BCLog::Level::Warning, "foo10: %s\n", "bar10"); // printed unconditionally

    std::vector<std::string> expected = {
        "[http:info] foo1: bar1",
        "[validation:warning] foo3: bar3",
        "[rpc:error] foo4: bar4",
        "[net:warning] foo5: bar5",
        "[net:error] foo7: bar7",
        "[all:info] foo8: bar8",
        "foo9: bar9",
        "[warning] foo10: bar10",
    };
    std::ifstream file{tmp_log_path};
    std::vector<std::string> log_lines;
    for (std::string log; std::getline(file, log);) {
        log_lines.push_back(log);
    }
    BOOST_CHECK_EQUAL_COLLECTIONS(log_lines.begin(), log_lines.end(), expected.begin(), expected.end());
}

BOOST_FIXTURE_TEST_CASE(logging_Conf, LogSetup)
{
    // No categories traced
    {
        ResetLogger();
        ArgsManager args;
        args.AddArg("-trace", "...", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
        const char* argv_test[] = {"bitcoind"};
        std::string err;
        BOOST_REQUIRE(args.ParseParameters(1, argv_test, err));

        auto result = init::SetLoggingCategories(args);
        BOOST_REQUIRE(result);

        BOOST_CHECK_EQUAL(LogInstance().GetCategoryMask(), 0);
        BOOST_CHECK_EQUAL(LogInstance().GetCategoryTraceMask(), 0);
    }

    // All traced categories
    {
        ResetLogger();
        ArgsManager args;
        args.AddArg("-trace", "...", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
        const char* argv_test[] = {"bitcoind", "-trace=1"};
        std::string err;
        BOOST_REQUIRE(args.ParseParameters(2, argv_test, err));

        auto result = init::SetLoggingCategories(args);
        BOOST_REQUIRE(result);

        BOOST_CHECK_EQUAL(LogInstance().GetCategoryMask(), BCLog::LogFlags::ALL);
        BOOST_CHECK_EQUAL(LogInstance().GetCategoryTraceMask(), BCLog::LogFlags::ALL);
    }

    // Specific traced categories
    {
        ResetLogger();
        ArgsManager args;
        args.AddArg("-debug", "...", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
        args.AddArg("-trace", "...", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
        const char* argv_test[] = {"bitcoind", "-trace=net", "-trace=http", "-debug=mempool"};
        std::string err;
        BOOST_REQUIRE(args.ParseParameters(4, argv_test, err));

        auto result = init::SetLoggingCategories(args);
        BOOST_REQUIRE(result);

        BOOST_CHECK_EQUAL(LogInstance().GetCategoryMask(), BCLog::LogFlags::NET | BCLog::LogFlags::HTTP | BCLog::LogFlags::MEMPOOL);
        BOOST_CHECK_EQUAL(LogInstance().GetCategoryTraceMask(), BCLog::LogFlags::NET | BCLog::LogFlags::HTTP);
    }
}

BOOST_FIXTURE_TEST_CASE(logging_IsNoneCategory, LogSetup)
{
    for (const char* const& c : {"none", "0"}) {
        BOOST_CHECK(LogInstance().IsNoneCategory(c));
    }
    for (const char* const& c : {"", "NONE", "net", "all", "1"}) {
        BOOST_CHECK(!LogInstance().IsNoneCategory(c));
    }
}

BOOST_AUTO_TEST_SUITE_END()
