// Copyright (c) 2016-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DEPLOYMENTINFO_H
#define BITCOIN_DEPLOYMENTINFO_H

#include <consensus/params.h>

#include <map>
#include <string>

struct VBDeploymentInfo {
    /** Deployment name */
    const char *name;
    /** Whether GBT clients can safely ignore this rule in simplified usage */
    bool gbt_force;
};

extern const VBDeploymentInfo VersionBitsDeploymentInfo[Consensus::MAX_VERSION_BITS_DEPLOYMENTS];

std::string DeploymentName(Consensus::BuriedDeployment dep);

inline std::string DeploymentName(Consensus::DeploymentPos pos)
{
    assert(Consensus::ValidDeployment(pos));
    return VersionBitsDeploymentInfo[pos].name;
}

extern const std::map<std::string, uint32_t> g_verify_flag_names;

std::string FormatScriptFlags(uint32_t flags);

bool BuriedException(Consensus::BuriedDeployment dep, uint32_t flags);

#endif // BITCOIN_DEPLOYMENTINFO_H
