// Copyright (c) 2011-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/optionsmodel.h>

#include <qt/bitcoinunits.h>
#include <qt/guiconstants.h>
#include <qt/guiutil.h>

#include <chainparams.h>
#include <interfaces/node.h>
#include <mapport.h>
#include <net.h>
#include <net_processing.h>
#include <netbase.h>
#include <node/context.h>
#include <outputtype.h>
#include <txdb.h>       // for -dbcache defaults
#include <util/string.h>
#include <validation.h> // For DEFAULT_SCRIPTCHECK_THREADS
#ifdef ENABLE_WALLET
#include <interfaces/wallet.h>
#include <wallet/wallet.h>
#endif

#include <QDebug>
#include <QLatin1Char>
#include <QSettings>
#include <QStringList>

const char *DEFAULT_GUI_PROXY_HOST = "127.0.0.1";

static const QString GetDefaultProxyAddress();

static const QLatin1String fontchoice_str_embedded{"embedded"};
static const QLatin1String fontchoice_str_best_system{"best_system"};
static const QString fontchoice_str_custom_prefix{QStringLiteral("custom, ")};

QString OptionsModel::FontChoiceToString(const OptionsModel::FontChoice& f)
{
    if (std::holds_alternative<FontChoiceAbstract>(f)) {
        if (f == UseBestSystemFont) {
            return fontchoice_str_best_system;
        } else {
            return fontchoice_str_embedded;
        }
    }
    return fontchoice_str_custom_prefix + std::get<QFont>(f).toString();
}

OptionsModel::FontChoice OptionsModel::FontChoiceFromString(const QString& s)
{
    if (s == fontchoice_str_best_system) {
        return FontChoiceAbstract::BestSystemFont;
    } else if (s == fontchoice_str_embedded) {
        return FontChoiceAbstract::EmbeddedFont;
    } else if (s.startsWith(fontchoice_str_custom_prefix)) {
        QFont f;
        f.fromString(s.mid(fontchoice_str_custom_prefix.size()));
        return f;
    } else {
        return FontChoiceAbstract::EmbeddedFont;  // default
    }
}

OptionsModel::OptionsModel(QObject *parent, bool resetSettings) :
    QAbstractListModel(parent)
{
    Init(resetSettings);
}

void OptionsModel::addOverriddenOption(const std::string &option)
{
    strOverriddenByCommandLine += QString::fromStdString(option) + "=" + QString::fromStdString(gArgs.GetArg(option, "")) + " ";
}

// Writes all missing QSettings with their default values
void OptionsModel::Init(bool resetSettings)
{
    if (resetSettings)
        Reset();

    checkAndMigrate();

    QSettings settings;

    // Ensure restart flag is unset on client startup
    setRestartRequired(false);

    // These are Qt-only settings:

    // Window
    if (!settings.contains("fHideTrayIcon")) {
        settings.setValue("fHideTrayIcon", false);
    }
    m_show_tray_icon = !settings.value("fHideTrayIcon").toBool();
    Q_EMIT showTrayIconChanged(m_show_tray_icon);

    if (!settings.contains("fMinimizeToTray"))
        settings.setValue("fMinimizeToTray", false);
    fMinimizeToTray = settings.value("fMinimizeToTray").toBool() && m_show_tray_icon;

    if (!settings.contains("fMinimizeOnClose"))
        settings.setValue("fMinimizeOnClose", false);
    fMinimizeOnClose = settings.value("fMinimizeOnClose").toBool();

    // Display
    if (!settings.contains("nDisplayUnit"))
        settings.setValue("nDisplayUnit", BitcoinUnits::BTC);
    nDisplayUnit = settings.value("nDisplayUnit").toInt();

    if (!settings.contains("strThirdPartyTxUrls"))
        settings.setValue("strThirdPartyTxUrls", "");
    strThirdPartyTxUrls = settings.value("strThirdPartyTxUrls", "").toString();

    if (!settings.contains("fCoinControlFeatures"))
        settings.setValue("fCoinControlFeatures", false);
    fCoinControlFeatures = settings.value("fCoinControlFeatures", false).toBool();

    if (!settings.contains("enable_psbt_controls")) {
        settings.setValue("enable_psbt_controls", false);
    }
    m_enable_psbt_controls = settings.value("enable_psbt_controls", false).toBool();

    // These are shared with the core or have a command-line parameter
    // and we want command-line parameters to overwrite the GUI settings.
    //
    // If setting doesn't exist create it with defaults.
    //
    // If gArgs.SoftSetArg() or gArgs.SoftSetBoolArg() return false we were overridden
    // by command-line and show this in the UI.

    // Main
    if (!gArgs.IsArgSet("-prune")) {
        if (settings.contains("bPrune")) {
            if (settings.value("bPrune").toBool()) {
                if (!settings.contains("nPruneSize"))
                    settings.setValue("nPruneSize", DEFAULT_PRUNE_TARGET_GB);
                const uint64_t nPruneSizeMiB = PruneGBtoMiB(settings.value("nPruneSize").toInt());
                gArgs.ForceSetArg("-prune", nPruneSizeMiB);
            } else {
                gArgs.ForceSetArg("-prune", "0");
            }
        }
    }

    if (!settings.contains("nDatabaseCache"))
        settings.setValue("nDatabaseCache", (qint64)nDefaultDbCache);
    if (!gArgs.SoftSetArg("-dbcache", settings.value("nDatabaseCache").toString().toStdString()))
        addOverriddenOption("-dbcache");

    if (!settings.contains("nThreadsScriptVerif"))
        settings.setValue("nThreadsScriptVerif", DEFAULT_SCRIPTCHECK_THREADS);
    if (!gArgs.SoftSetArg("-par", settings.value("nThreadsScriptVerif").toString().toStdString()))
        addOverriddenOption("-par");

    if (!settings.contains("strDataDir"))
        settings.setValue("strDataDir", GUIUtil::getDefaultDataDirectory());

    // Wallet
#ifdef ENABLE_WALLET
    if (!settings.contains("bSpendZeroConfChange"))
        settings.setValue("bSpendZeroConfChange", true);
    if (!gArgs.SoftSetBoolArg("-spendzeroconfchange", settings.value("bSpendZeroConfChange").toBool()))
        addOverriddenOption("-spendzeroconfchange");

    if (!settings.contains("external_signer_path"))
        settings.setValue("external_signer_path", "");

    if (!gArgs.SoftSetArg("-signer", settings.value("external_signer_path").toString().toStdString())) {
        addOverriddenOption("-signer");
    }

    if (!settings.contains("SubFeeFromAmount")) {
        settings.setValue("SubFeeFromAmount", false);
    }
    m_sub_fee_from_amount = settings.value("SubFeeFromAmount", false).toBool();
#endif

    // Network
    if (!settings.contains("nNetworkPort"))
        settings.setValue("nNetworkPort", (quint16)Params().GetDefaultPort());
    if (!gArgs.SoftSetArg("-port", settings.value("nNetworkPort").toString().toStdString()))
        addOverriddenOption("-port");

    if (!settings.contains("fUseUPnP"))
        settings.setValue("fUseUPnP", DEFAULT_UPNP);
    if (!gArgs.SoftSetBoolArg("-upnp", settings.value("fUseUPnP").toBool()))
        addOverriddenOption("-upnp");

    if (!settings.contains("fUseNatpmp")) {
        settings.setValue("fUseNatpmp", DEFAULT_NATPMP);
    }
    if (!gArgs.SoftSetBoolArg("-natpmp", settings.value("fUseNatpmp").toBool())) {
        addOverriddenOption("-natpmp");
    }

    if (!settings.contains("fListen"))
        settings.setValue("fListen", DEFAULT_LISTEN);
    if (!gArgs.SoftSetBoolArg("-listen", settings.value("fListen").toBool())) {
        addOverriddenOption("-listen");
    } else if (!settings.value("fListen").toBool()) {
        gArgs.SoftSetBoolArg("-listenonion", false);
    }

    if (!settings.contains("server")) {
        settings.setValue("server", false);
    }
    if (!gArgs.SoftSetBoolArg("-server", settings.value("server").toBool())) {
        addOverriddenOption("-server");
    }

    if (!settings.contains("fUseProxy"))
        settings.setValue("fUseProxy", false);
    if (!settings.contains("addrProxy"))
        settings.setValue("addrProxy", GetDefaultProxyAddress());
    // Only try to set -proxy, if user has enabled fUseProxy
    if ((settings.value("fUseProxy").toBool() && !gArgs.SoftSetArg("-proxy", settings.value("addrProxy").toString().toStdString())))
        addOverriddenOption("-proxy");
    else if(!settings.value("fUseProxy").toBool() && !gArgs.GetArg("-proxy", "").empty())
        addOverriddenOption("-proxy");

    if (!settings.contains("fUseSeparateProxyTor"))
        settings.setValue("fUseSeparateProxyTor", false);
    if (!settings.contains("addrSeparateProxyTor"))
        settings.setValue("addrSeparateProxyTor", GetDefaultProxyAddress());
    // Only try to set -onion, if user has enabled fUseSeparateProxyTor
    if ((settings.value("fUseSeparateProxyTor").toBool() && !gArgs.SoftSetArg("-onion", settings.value("addrSeparateProxyTor").toString().toStdString())))
        addOverriddenOption("-onion");
    else if(!settings.value("fUseSeparateProxyTor").toBool() && !gArgs.GetArg("-onion", "").empty())
        addOverriddenOption("-onion");

    // rwconf settings that require a restart
    f_peerbloomfilters = gArgs.GetBoolArg("-peerbloomfilters", DEFAULT_PEERBLOOMFILTERS);

    // Display
    if (!settings.contains("language"))
        settings.setValue("language", "");
    if (!gArgs.SoftSetArg("-lang", settings.value("language").toString().toStdString()))
        addOverriddenOption("-lang");

    language = settings.value("language").toString();

    if (settings.contains("FontForMoney")) {
        m_font_money = FontChoiceFromString(settings.value("FontForMoney").toString());
    } else if (settings.contains("UseEmbeddedMonospacedFont")) {
        if (settings.value("UseEmbeddedMonospacedFont").toBool()) {
            m_font_money = FontChoiceAbstract::EmbeddedFont;
        } else {
            m_font_money = FontChoiceAbstract::BestSystemFont;
        }
    }
    Q_EMIT fontForMoneyChanged(getFontForMoney());

    if (settings.contains("FontForQRCodes")) {
        m_font_qrcodes = FontChoiceFromString(settings.value("FontForQRCodes").toString());
    }
    Q_EMIT fontForQRCodesChanged(getFontChoiceForQRCodes());

    if (!settings.contains("PeersTabAlternatingRowColors")) {
        settings.setValue("PeersTabAlternatingRowColors", "false");
    }
    m_peers_tab_alternating_row_colors = settings.value("PeersTabAlternatingRowColors").toBool();
    Q_EMIT peersTabAlternatingRowColorsChanged(m_peers_tab_alternating_row_colors);
}

/** Helper function to copy contents from one QSettings to another.
 * By using allKeys this also covers nested settings in a hierarchy.
 */
static void CopySettings(QSettings& dst, const QSettings& src)
{
    for (const QString& key : src.allKeys()) {
        dst.setValue(key, src.value(key));
    }
}

/** Back up a QSettings to an ini-formatted file. */
static void BackupSettings(const fs::path& filename, const QSettings& src)
{
    qInfo() << "Backing up GUI settings to" << GUIUtil::PathToQString(filename);
    QSettings dst(GUIUtil::PathToQString(filename), QSettings::IniFormat);
    dst.clear();
    CopySettings(dst, src);
}

void OptionsModel::Reset()
{
    QSettings settings;

    // Backup old settings to chain-specific datadir for troubleshooting
    BackupSettings(gArgs.GetDataDirNet() / "guisettings.ini.bak", settings);

    // Save the strDataDir setting
    QString dataDir = GUIUtil::getDefaultDataDirectory();
    dataDir = settings.value("strDataDir", dataDir).toString();

    // Remove rw config file
    gArgs.EraseRWConfigFile();

    // Remove all entries from our QSettings object
    settings.clear();

    // Set strDataDir
    settings.setValue("strDataDir", dataDir);

    // Set prune option iff it was configured in rwconf
    if (gArgs.RWConfigHasPruneOption()) {
        SetPruneMiB(gArgs.GetIntArg("-prune", 0), false);
    }

    // Set that this was reset
    settings.setValue("fReset", true);

    // default setting for OptionsModel::StartAtStartup - disabled
    if (GUIUtil::GetStartOnSystemStartup())
        GUIUtil::SetStartOnSystemStartup(false);
}

int OptionsModel::rowCount(const QModelIndex & parent) const
{
    return OptionIDRowCount;
}

struct ProxySetting {
    bool is_set;
    QString ip;
    QString port;
};

static ProxySetting GetProxySetting(QSettings &settings, const QString &name)
{
    static const ProxySetting default_val = {false, DEFAULT_GUI_PROXY_HOST, QString("%1").arg(DEFAULT_GUI_PROXY_PORT)};
    // Handle the case that the setting is not set at all
    if (!settings.contains(name)) {
        return default_val;
    }
    // contains IP at index 0 and port at index 1
    QStringList ip_port = GUIUtil::SplitSkipEmptyParts(settings.value(name).toString(), ":");
    if (ip_port.size() == 2) {
        return {true, ip_port.at(0), ip_port.at(1)};
    } else { // Invalid: return default
        return default_val;
    }
}

static void SetProxySetting(QSettings &settings, const QString &name, const ProxySetting &ip_port)
{
    settings.setValue(name, QString{ip_port.ip + QLatin1Char(':') + ip_port.port});
}

static const QString GetDefaultProxyAddress()
{
    return QString("%1:%2").arg(DEFAULT_GUI_PROXY_HOST).arg(DEFAULT_GUI_PROXY_PORT);
}

void OptionsModel::SetPruneMiB(int64_t prune_target_mib, bool force)
{
    const bool prune = prune_target_mib > 1;
    QSettings settings;
    settings.setValue("bPrune", prune);
    if (prune) {
        const int prune_target_gb = PruneMiBtoGB(prune_target_mib);
        settings.setValue("nPruneSize", prune_target_gb);
    }
    std::string prune_val = ToString(prune_target_mib);
    gArgs.ModifyRWConfigFile("prune", prune_val);
    if (force) {
        gArgs.ForceSetArg("-prune", prune_val);
        return;
    }
    if (!gArgs.SoftSetArg("-prune", prune_val)) {
        addOverriddenOption("-prune");
    }
}

// read QSettings values and return them
QVariant OptionsModel::data(const QModelIndex & index, int role) const
{
    if(role == Qt::EditRole)
    {
        QSettings settings;
        switch(index.row())
        {
        case StartAtStartup:
            return GUIUtil::GetStartOnSystemStartup();
        case ShowTrayIcon:
            return m_show_tray_icon;
        case MinimizeToTray:
            return fMinimizeToTray;
        case NetworkPort:
            return settings.value("nNetworkPort");
        case MapPortUPnP:
#ifdef USE_UPNP
            return settings.value("fUseUPnP");
#else
            return false;
#endif // USE_UPNP
        case MapPortNatpmp:
#ifdef USE_NATPMP
            return settings.value("fUseNatpmp");
#else
            return false;
#endif // USE_NATPMP
        case MinimizeOnClose:
            return fMinimizeOnClose;

        // default proxy
        case ProxyUse:
            return settings.value("fUseProxy", false);
        case ProxyIP:
            return GetProxySetting(settings, "addrProxy").ip;
        case ProxyPort:
            return GetProxySetting(settings, "addrProxy").port;

        // separate Tor proxy
        case ProxyUseTor:
            return settings.value("fUseSeparateProxyTor", false);
        case ProxyIPTor:
            return GetProxySetting(settings, "addrSeparateProxyTor").ip;
        case ProxyPortTor:
            return GetProxySetting(settings, "addrSeparateProxyTor").port;

#ifdef ENABLE_WALLET
        case SpendZeroConfChange:
            return settings.value("bSpendZeroConfChange");
        case ExternalSignerPath:
            return settings.value("external_signer_path");
        case SubFeeFromAmount:
            return m_sub_fee_from_amount;
        case addresstype:
        {
            const OutputType default_address_type = ParseOutputType(gArgs.GetArg("-addresstype", "")).value_or(wallet::DEFAULT_ADDRESS_TYPE);
            return QString::fromStdString(FormatOutputType(default_address_type));
        }
#endif
        case DisplayUnit:
            return nDisplayUnit;
        case ThirdPartyTxUrls:
            return strThirdPartyTxUrls;
        case Language:
            return settings.value("language");
        case FontForMoney:
            return QVariant::fromValue(m_font_money);
        case FontForQRCodes:
            return QVariant::fromValue(m_font_qrcodes);
        case PeersTabAlternatingRowColors:
            return m_peers_tab_alternating_row_colors;
        case CoinControlFeatures:
            return fCoinControlFeatures;
        case EnablePSBTControls:
            return settings.value("enable_psbt_controls");
        case PruneMiB:
            return qlonglong(gArgs.GetIntArg("-prune", 0));
        case DatabaseCache:
            return settings.value("nDatabaseCache");
        case ThreadsScriptVerif:
            return settings.value("nThreadsScriptVerif");
        case Listen:
            return settings.value("fListen");
        case Server:
            return settings.value("server");
        case maxuploadtarget:
            return qlonglong(node().context()->connman->GetMaxOutboundTarget() / 1024 / 1024);
        case peerbloomfilters:
            return f_peerbloomfilters;
        default:
            return QVariant();
        }
    }
    return QVariant();
}

// write QSettings values
bool OptionsModel::setData(const QModelIndex & index, const QVariant & value, int role)
{
    bool successful = true; /* set to false on parse error */
    if(role == Qt::EditRole)
    {
        QSettings settings;
        switch(index.row())
        {
        case StartAtStartup:
            successful = GUIUtil::SetStartOnSystemStartup(value.toBool());
            break;
        case ShowTrayIcon:
            m_show_tray_icon = value.toBool();
            settings.setValue("fHideTrayIcon", !m_show_tray_icon);
            Q_EMIT showTrayIconChanged(m_show_tray_icon);
            break;
        case MinimizeToTray:
            fMinimizeToTray = value.toBool();
            settings.setValue("fMinimizeToTray", fMinimizeToTray);
            break;
        case NetworkPort:
            if (settings.value("nNetworkPort") != value) {
                // If the port input box is empty, set to default port
                if (value.toString().isEmpty()) {
                    settings.setValue("nNetworkPort", (quint16)Params().GetDefaultPort());
                }
                else {
                    settings.setValue("nNetworkPort", (quint16)value.toInt());
                }
                setRestartRequired(true);
            }
            break;
        case MapPortUPnP: // core option - can be changed on-the-fly
            settings.setValue("fUseUPnP", value.toBool());
            break;
        case MapPortNatpmp: // core option - can be changed on-the-fly
            settings.setValue("fUseNatpmp", value.toBool());
            break;
        case MinimizeOnClose:
            fMinimizeOnClose = value.toBool();
            settings.setValue("fMinimizeOnClose", fMinimizeOnClose);
            break;

        // default proxy
        case ProxyUse:
            if (settings.value("fUseProxy") != value) {
                settings.setValue("fUseProxy", value.toBool());
                setRestartRequired(true);
            }
            break;
        case ProxyIP: {
            auto ip_port = GetProxySetting(settings, "addrProxy");
            if (!ip_port.is_set || ip_port.ip != value.toString()) {
                ip_port.ip = value.toString();
                SetProxySetting(settings, "addrProxy", ip_port);
                setRestartRequired(true);
            }
        }
        break;
        case ProxyPort: {
            auto ip_port = GetProxySetting(settings, "addrProxy");
            if (!ip_port.is_set || ip_port.port != value.toString()) {
                ip_port.port = value.toString();
                SetProxySetting(settings, "addrProxy", ip_port);
                setRestartRequired(true);
            }
        }
        break;

        // separate Tor proxy
        case ProxyUseTor:
            if (settings.value("fUseSeparateProxyTor") != value) {
                settings.setValue("fUseSeparateProxyTor", value.toBool());
                setRestartRequired(true);
            }
            break;
        case ProxyIPTor: {
            auto ip_port = GetProxySetting(settings, "addrSeparateProxyTor");
            if (!ip_port.is_set || ip_port.ip != value.toString()) {
                ip_port.ip = value.toString();
                SetProxySetting(settings, "addrSeparateProxyTor", ip_port);
                setRestartRequired(true);
            }
        }
        break;
        case ProxyPortTor: {
            auto ip_port = GetProxySetting(settings, "addrSeparateProxyTor");
            if (!ip_port.is_set || ip_port.port != value.toString()) {
                ip_port.port = value.toString();
                SetProxySetting(settings, "addrSeparateProxyTor", ip_port);
                setRestartRequired(true);
            }
        }
        break;

#ifdef ENABLE_WALLET
        case SpendZeroConfChange:
            if (settings.value("bSpendZeroConfChange") != value) {
                settings.setValue("bSpendZeroConfChange", value);
                setRestartRequired(true);
            }
            break;
        case ExternalSignerPath:
            if (settings.value("external_signer_path") != value.toString()) {
                settings.setValue("external_signer_path", value.toString());
                setRestartRequired(true);
            }
            break;
        case SubFeeFromAmount:
            m_sub_fee_from_amount = value.toBool();
            settings.setValue("SubFeeFromAmount", m_sub_fee_from_amount);
            break;
        case addresstype:
        {
            const std::string newvalue_str = value.toString().toStdString();
            const OutputType oldvalue = ParseOutputType(gArgs.GetArg("-addresstype", "")).value_or(wallet::DEFAULT_ADDRESS_TYPE);
            const OutputType newvalue = ParseOutputType(newvalue_str).value_or(oldvalue);
            if (newvalue != oldvalue) {
                gArgs.ModifyRWConfigFile("addresstype", newvalue_str);
                gArgs.ForceSetArg("-addresstype", newvalue_str);
                for (auto& wallet_interface : m_node->walletLoader().getWallets()) {
                    wallet::CWallet *wallet;
                    if (wallet_interface && (wallet = wallet_interface->wallet())) {
                        wallet->m_default_address_type = newvalue;
                    } else {
                        setRestartRequired(true);
                        continue;
                    }
                }
            }
            break;
        }
#endif
        case DisplayUnit:
            setDisplayUnit(value);
            break;
        case ThirdPartyTxUrls:
            if (strThirdPartyTxUrls != value.toString()) {
                strThirdPartyTxUrls = value.toString();
                settings.setValue("strThirdPartyTxUrls", strThirdPartyTxUrls);
                setRestartRequired(true);
            }
            break;
        case Language:
            if (settings.value("language") != value) {
                settings.setValue("language", value);
                setRestartRequired(true);
            }
            break;
        case FontForMoney:
        {
            const auto& new_font = value.value<FontChoice>();
            if (m_font_money == new_font) break;
            settings.setValue("FontForMoney", FontChoiceToString(new_font));
            m_font_money = new_font;
            Q_EMIT fontForMoneyChanged(getFontForMoney());
            break;
        }
        case FontForQRCodes:
        {
            const auto& new_font = value.value<FontChoice>();
            if (m_font_qrcodes == new_font) break;
            settings.setValue("FontForQRCodes", FontChoiceToString(new_font));
            m_font_qrcodes = new_font;
            Q_EMIT fontForQRCodesChanged(new_font);
            break;
        }
        case PeersTabAlternatingRowColors:
            m_peers_tab_alternating_row_colors = value.toBool();
            settings.setValue("PeersTabAlternatingRowColors", m_peers_tab_alternating_row_colors);
            Q_EMIT peersTabAlternatingRowColorsChanged(m_peers_tab_alternating_row_colors);
            break;
        case CoinControlFeatures:
            fCoinControlFeatures = value.toBool();
            settings.setValue("fCoinControlFeatures", fCoinControlFeatures);
            Q_EMIT coinControlFeaturesChanged(fCoinControlFeatures);
            break;
        case EnablePSBTControls:
            m_enable_psbt_controls = value.toBool();
            settings.setValue("enable_psbt_controls", m_enable_psbt_controls);
            break;
        case PruneMiB:
        {
            const qlonglong llvalue = value.toLongLong();
            if (gArgs.GetIntArg("-prune", 0) != llvalue) {
                gArgs.ModifyRWConfigFile("prune", value.toString().toStdString());
                settings.setValue("bPrune", (llvalue > 1));
                if (llvalue > 1) {
                    settings.setValue("nPruneSize", PruneMiBtoGB(llvalue));
                }
                setRestartRequired(true);
            }
            break;
        }
        case DatabaseCache:
            if (settings.value("nDatabaseCache") != value) {
                settings.setValue("nDatabaseCache", value);
                setRestartRequired(true);
            }
            break;
        case ThreadsScriptVerif:
            if (settings.value("nThreadsScriptVerif") != value) {
                settings.setValue("nThreadsScriptVerif", value);
                setRestartRequired(true);
            }
            break;
        case Listen:
            if (settings.value("fListen") != value) {
                settings.setValue("fListen", value);
                setRestartRequired(true);
            }
            break;
        case Server:
            if (settings.value("server") != value) {
                settings.setValue("server", value);
                setRestartRequired(true);
            }
            break;
        case maxuploadtarget:
        {
            qlonglong nv = value.toLongLong();
            if (node().context()->connman->GetMaxOutboundTarget() / 1024 / 1024 != uint64_t(nv)) {
                gArgs.ModifyRWConfigFile("maxuploadtarget", value.toString().toStdString());
                node().context()->connman->SetMaxOutboundTarget(nv * 1024 * 1024);
            }
            break;
        }
        case peerbloomfilters:
            if (f_peerbloomfilters != value) {
                gArgs.ModifyRWConfigFile("peerbloomfilters", strprintf("%d", value.toBool()));
                f_peerbloomfilters = value.toBool();
                setRestartRequired(true);
            }
            break;
        default:
            break;
        }
    }

    Q_EMIT dataChanged(index, index);

    return successful;
}

/** Updates current unit in memory, settings and emits displayUnitChanged(newUnit) signal */
void OptionsModel::setDisplayUnit(const QVariant &value)
{
    if (!value.isNull())
    {
        QSettings settings;
        nDisplayUnit = value.toInt();
        settings.setValue("nDisplayUnit", nDisplayUnit);
        Q_EMIT displayUnitChanged(nDisplayUnit);
    }
}

QFont OptionsModel::getFontForChoice(const FontChoice& fc)
{
    QFont f;
    if (std::holds_alternative<FontChoiceAbstract>(fc)) {
        f = GUIUtil::fixedPitchFont(fc != UseBestSystemFont);
        f.setWeight(QFont::Bold);
    } else {
        f = std::get<QFont>(fc);
    }
    return f;
}

QFont OptionsModel::getFontForMoney() const
{
    return getFontForChoice(m_font_money);
}

void OptionsModel::setRestartRequired(bool fRequired)
{
    QSettings settings;
    return settings.setValue("fRestartRequired", fRequired);
}

bool OptionsModel::isRestartRequired() const
{
    QSettings settings;
    return settings.value("fRestartRequired", false).toBool();
}

void OptionsModel::checkAndMigrate()
{
    // Migration of default values
    // Check if the QSettings container was already loaded with this client version
    QSettings settings;
    static const char strSettingsVersionKey[] = "nSettingsVersion";
    int settingsVersion = settings.contains(strSettingsVersionKey) ? settings.value(strSettingsVersionKey).toInt() : 0;
    if (settingsVersion < CLIENT_VERSION)
    {
        // -dbcache was bumped from 100 to 300 in 0.13
        // see https://github.com/bitcoin/bitcoin/pull/8273
        // force people to upgrade to the new value if they are using 100MB
        if (settingsVersion < 130000 && settings.contains("nDatabaseCache") && settings.value("nDatabaseCache").toLongLong() == 100)
            settings.setValue("nDatabaseCache", (qint64)nDefaultDbCache);

        settings.setValue(strSettingsVersionKey, CLIENT_VERSION);
    }

    // Overwrite the 'addrProxy' setting in case it has been set to an illegal
    // default value (see issue #12623; PR #12650).
    if (settings.contains("addrProxy") && settings.value("addrProxy").toString().endsWith("%2")) {
        settings.setValue("addrProxy", GetDefaultProxyAddress());
    }

    // Overwrite the 'addrSeparateProxyTor' setting in case it has been set to an illegal
    // default value (see issue #12623; PR #12650).
    if (settings.contains("addrSeparateProxyTor") && settings.value("addrSeparateProxyTor").toString().endsWith("%2")) {
        settings.setValue("addrSeparateProxyTor", GetDefaultProxyAddress());
    }
}
