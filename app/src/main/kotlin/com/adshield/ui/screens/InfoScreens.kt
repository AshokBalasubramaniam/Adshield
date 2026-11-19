package com.adshield.ui.screens

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.provider.Settings
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.KeyboardArrowRight
import androidx.compose.material.icons.rounded.BatteryChargingFull
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.PrivacyTip
import androidx.compose.material.icons.rounded.Rule
import androidx.compose.material.icons.rounded.Wifi
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adshield.BuildConfig
import com.adshield.ui.components.BodyText
import com.adshield.ui.components.IconBadge
import com.adshield.ui.components.InfoRow
import com.adshield.ui.components.Panel
import com.adshield.ui.components.Pill
import com.adshield.ui.components.ScreenScaffold
import com.adshield.ui.components.SectionTitle
import com.adshield.ui.theme.Palette

private fun Context.openSettings(intent: Intent) {
    try {
        startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    } catch (_: ActivityNotFoundException) {
        runCatching { startActivity(Intent(Settings.ACTION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
    }
}

@Composable
private fun TextBlock(heading: String, vararg paragraphs: String) {
    Panel {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(heading, style = MaterialTheme.typography.titleMedium)
            paragraphs.forEach { BodyText(it, color = MaterialTheme.colorScheme.onSurfaceVariant) }
        }
    }
}

@Composable
private fun InfoList(padding: PaddingValues, content: androidx.compose.foundation.lazy.LazyListScope.() -> Unit) {
    LazyColumn(
        Modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = padding.calculateTopPadding() + 4.dp, bottom = padding.calculateBottomPadding() + 24.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
        content = content,
    )
}

// ---------- More menu ----------

@Composable
fun MoreScreen(
    onDns: () -> Unit, onRules: () -> Unit, onNetwork: () -> Unit,
    onBattery: () -> Unit, onPrivacy: () -> Unit, onAbout: () -> Unit,
) {
    ScreenScaffold(title = "More") { padding ->
        InfoList(padding) {
            item { MenuRow("DNS filtering", "Block response, upstream DNS, leak protection", Icons.Rounded.Dns, onDns) }
            item { MenuRow("Allow & block rules", "Domains to always allow or always block", Icons.Rounded.Rule, onRules) }
            item { MenuRow("Network status", "Connection, DNS path and leak check", Icons.Rounded.Wifi, onNetwork) }
            item { MenuRow("Battery optimization guide", "Keep protection running reliably", Icons.Rounded.BatteryChargingFull, onBattery) }
            item { MenuRow("Privacy policy", "What is processed, stored and never collected", Icons.Rounded.PrivacyTip, onPrivacy) }
            item { MenuRow("About AdShield", "Version, licenses and limitations", Icons.Rounded.Info, onAbout) }
        }
    }
}

@Composable
private fun MenuRow(title: String, subtitle: String, icon: androidx.compose.ui.graphics.vector.ImageVector, onClick: () -> Unit) {
    Panel(onClick = onClick) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
            IconBadge(icon)
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                BodyText(subtitle)
            }
            Icon(Icons.AutoMirrored.Rounded.KeyboardArrowRight, null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

// ---------- Battery ----------

@Composable
fun BatteryGuideScreen(onBack: (() -> Unit)?, vm: DashboardViewModel = hiltViewModel()) {
    val context = LocalContext.current
    val load by vm.load.collectAsStateWithLifecycle()
    ScreenScaffold(title = "Battery optimization", onBack = onBack) { padding ->
        InfoList(padding) {
            item {
                Panel {
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text("How AdShield saves battery", style = MaterialTheme.typography.titleMedium)
                        BodyText("•  Only DNS lookups enter the tunnel. Video, browsing and downloads never pass through AdShield.", color = MaterialTheme.colorScheme.onSurface)
                        BodyText("•  Rule lookups are hash-based and cached; answers are cached by their TTL.", color = MaterialTheme.colorScheme.onSurface)
                        BodyText("•  No wake locks, no boot receiver and no background scheduler. Filter lists refresh only while protection is on, on unmetered networks, when the battery is not low.", color = MaterialTheme.colorScheme.onSurface)
                    }
                }
            }
            item { SectionTitle("Right now") }
            item {
                Panel {
                    Column {
                        InfoRow("AdShield CPU use", "${"%.1f".format(load.cpuPercent)}%")
                        InfoRow("Lookups per minute", load.queriesPerMinute.toString())
                        InfoRow("Load", load.level.label)
                        BodyText("Android does not let apps read their own battery attribution. For the system's figure open Settings › Battery › AdShield.")
                    }
                }
            }
            item { SectionTitle("Keep protection running") }
            item {
                TextBlock(
                    "1. Exempt AdShield from battery optimization",
                    "Some phone makers stop background apps aggressively. If protection switches itself off, allow AdShield to run unrestricted. VPN apps already get special treatment on most devices, so this is only needed if you see unexpected stops.",
                )
            }
            item {
                Button(
                    onClick = { context.openSettings(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)) }, modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = Palette.Teal, contentColor = Palette.OnTeal),
                ) { Text("Open battery optimization settings") }
            }
            item {
                OutlinedButton(onClick = { context.openSettings(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, "package:${context.packageName}".toUri())) }, modifier = Modifier.fillMaxWidth()) {
                    Text("Open AdShield app info")
                }
            }
            item {
                TextBlock(
                    "2. Optional: Always-on VPN",
                    "In Android's VPN settings you can mark AdShield as Always-on, so Android restarts it after reboots or crashes.",
                    "Do not enable “Block connections without VPN” unless you want your internet to stop whenever AdShield is not running.",
                )
            }
            item { OutlinedButton(onClick = { context.openSettings(Intent(Settings.ACTION_VPN_SETTINGS)) }, modifier = Modifier.fillMaxWidth()) { Text("Open VPN settings") } }
            item {
                TextBlock(
                    "3. Recovery",
                    "If the VPN interface drops, AdShield retries with increasing delays and tells you if it gives up. It never shows “Protected” unless the tunnel is actually processing DNS.",
                )
            }
        }
    }
}

// ---------- Privacy ----------

@Composable
fun PrivacyScreen(onBack: (() -> Unit)?) {
    ScreenScaffold(title = "Privacy policy", onBack = onBack) { padding ->
        InfoList(padding) {
            item {
                TextBlock(
                    "In short",
                    "AdShield filters DNS on your device. It has no accounts, no analytics, no advertising and no servers of its own. Nothing about your browsing is sent to the developer or anyone else by AdShield.",
                )
            }
            item {
                TextBlock(
                    "What the local filter sees",
                    "To decide whether to block a lookup, AdShield reads DNS queries that apps on your device make: the domain name asked for, the record type (such as A or AAAA), and, when Android allows it, which app asked. This happens in memory, on the device.",
                    "AdShield cannot see page content, URLs, searches, passwords or messages. It never intercepts or decrypts HTTPS.",
                )
            }
            item {
                TextBlock(
                    "What is stored on the device",
                    "•  Counters: total, allowed, blocked per type, per app, per day (last 30 days). No domain names are stored.\n•  Your settings, allow/block rules, per-app switches and added blocklists.\n•  Downloaded filter lists.\n•  A list of the 50 most recently blocked domain names is held in memory only. It is never written to disk and is cleared when protection stops or statistics are reset.",
                    "Reset statistics erases all counters. Uninstalling AdShield erases everything. Backups are disabled so this data is never copied to cloud backup.",
                )
            }
            item {
                TextBlock(
                    "Network connections AdShield makes",
                    "•  Filter list downloads (when you update, or automatically while protection is on if you allow it) go directly from your device to the list publishers' servers (GitHub, GitLab and others listed on the Blocklists screen) over HTTPS. Those hosts can see your device's IP address, like any download.\n•  Lookups you allow are forwarded to your upstream DNS: your network's DNS servers by default, or the custom server or DNS-over-HTTPS provider you choose. That provider sees those lookups, as it would without AdShield.\n•  Nothing is sent to the developer.",
                )
            }
            item {
                TextBlock(
                    "Permissions",
                    "•  Internet and network state: download lists, forward DNS, adapt to Wi-Fi/mobile changes.\n•  VPN (system consent dialog): create the local DNS-filtering interface.\n•  Foreground service and notifications: show that protection is active.\n•  Package visibility for apps with a launcher icon: the per-app screen.\nAdShield does not request location, contacts, storage, phone, camera, microphone or advertising ID.",
                )
            }
            item {
                TextBlock(
                    "Your control",
                    "Turn protection off at any time. Exclude individual apps. Clear statistics. Remove any list or rule. Change or remove your upstream DNS choice.",
                )
            }
        }
    }
}

// ---------- About ----------

@Composable
fun AboutScreen(onBack: (() -> Unit)?) {
    ScreenScaffold(title = "About", onBack = onBack) { padding ->
        InfoList(padding) {
            item {
                Panel {
                    Column {
                        Text("AdShield", style = MaterialTheme.typography.headlineMedium)
                        BodyText("A private, local DNS ad and tracker blocker for Android.")
                        Spacer(Modifier.height(8.dp))
                        InfoRow("Version", "${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
                        InfoRow("Mechanism", "Local VpnService, DNS only")
                        InfoRow("Servers operated by AdShield", "None")
                        InfoRow("Analytics / ads / trackers", "None")
                    }
                }
            }
            item {
                TextBlock(
                    "What AdShield will not claim",
                    "AdShield blocks advertising, tracking, malware and phishing domains. It cannot guarantee that every ad disappears.",
                    "Ads delivered from the same servers as content, including many in-stream video ads in YouTube and JioHotstar, cannot be separated from the video by DNS filtering. AdShield has not been verified to remove ads in any specific version of these apps.",
                    "AdShield does not bypass subscriptions, DRM, sign-in or payment systems, does not modify other apps, does not inject code and does not fake ad completion.",
                )
            }
            item {
                TextBlock(
                    "Filter list credits",
                    "AdAway default blocklist (CC BY 3.0) · 1Hosts Lite by badmojr (MPL-2.0) · URLhaus by abuse.ch via malware-filter (CC0) · phishing-filter by malware-filter (OpenPhish, PhishTank, IPThreat feeds; non-commercial terms apply) · AdShield bundled seed lists (Apache-2.0).",
                    "Please support the maintainers of these lists.",
                )
            }
            item { Row { Pill("Open, auditable, local", Palette.Teal) } }
        }
    }
}

