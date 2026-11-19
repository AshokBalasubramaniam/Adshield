package com.adshield.ui.screens

import android.content.Context
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.RadioButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.adshield.data.db.BlocklistDao
import com.adshield.data.repo.AppRepository
import com.adshield.data.repo.NetworkMonitor
import com.adshield.data.repo.PrivateDnsMode
import com.adshield.data.repo.ProtectionStateHolder
import com.adshield.data.repo.UserRuleRepository
import com.adshield.data.rules.RuleManager
import com.adshield.data.settings.DnsSettings
import com.adshield.data.settings.SettingsRepository
import com.adshield.domain.model.BlockCategory
import com.adshield.domain.model.BlocklistSource
import com.adshield.domain.model.EngineStatus
import com.adshield.domain.model.NetworkStatus
import com.adshield.domain.model.ProtectionState
import com.adshield.domain.model.YoutubeProfile
import com.adshield.ui.components.BodyText
import com.adshield.ui.components.InfoRow
import com.adshield.ui.components.Panel
import com.adshield.ui.components.Pill
import com.adshield.ui.components.ScreenScaffold
import com.adshield.ui.components.SectionTitle
import com.adshield.ui.components.StatTile
import com.adshield.ui.components.SwitchRow
import com.adshield.ui.components.formatCount
import com.adshield.ui.theme.Palette
import com.adshield.youtube.DiagnosticsSnapshot
import com.adshield.youtube.LogEntry
import com.adshield.youtube.Verdict
import com.adshield.youtube.YoutubeClass
import com.adshield.youtube.YoutubeClassifier
import com.adshield.youtube.YoutubeDiagnostics
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import java.security.MessageDigest
import java.text.DateFormat
import java.util.Date
import javax.inject.Inject

// ---------------------------------------------------------------- state

enum class YoutubeStatus(val headline: String) {
    APP_MISSING("YouTube app not found"),
    PROTECTION_OFF("AdShield protection is off"),
    APP_EXCLUDED("YouTube is excluded from filtering"),
    ACTIVE_LIMITED("DNS filtering active for YouTube · limited"),
}

data class YoutubeUi(
    val installed: Boolean,
    val version: String?,
    val versionCode: Long,
    val systemApp: Boolean,
    val installer: String?,
    val protection: ProtectionState,
    val appFilteringEnabled: Boolean,
    val dns: DnsSettings,
    val network: NetworkStatus,
    val privateDns: PrivateDnsMode.Mode,
    val privateDnsHost: String?,
    val engine: EngineStatus,
    val sources: List<BlocklistSource>,
    val rulesVersion: String,
    val lastUpdate: Long,
    val snapshot: DiagnosticsSnapshot,
    val entries: List<LogEntry>,
) {
    val status: YoutubeStatus
        get() = when {
            !installed -> YoutubeStatus.APP_MISSING
            protection !is ProtectionState.Running -> YoutubeStatus.PROTECTION_OFF
            !appFilteringEnabled -> YoutubeStatus.APP_EXCLUDED
            else -> YoutubeStatus.ACTIVE_LIMITED
        }
}

/** Derived, evidence-based statement about playback; never a claim about ad removal. */
fun playbackCompatibility(s: DiagnosticsSnapshot, running: Boolean): Pair<String, Color> {
    val problems = s.playbackCriticalProblems
    val videoSeen = s.counts[YoutubeClass.VIDEO_CDN]?.values?.sum() ?: 0
    return when {
        !running -> "Not measured: protection is off." to Palette.TextSecondary
        problems > 0 -> "At risk: $problems playback-critical lookup(s) were blocked or failed this session. Open the log, filter by Problems." to Palette.Warning
        videoSeen > 0 -> "No playback-critical lookup was blocked or failed this session (video delivery lookups seen: $videoSeen)." to Palette.Teal
        s.totalRelated == 0L -> "No YouTube-related lookups observed yet. Play a video." to Palette.TextSecondary
        else -> "No video-delivery lookups seen yet, so playback has not been exercised." to Palette.TextSecondary
    }
}

@HiltViewModel
class YoutubeViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
    private val diagnostics: YoutubeDiagnostics,
    private val appRepo: AppRepository,
    private val settings: SettingsRepository,
    private val rules: UserRuleRepository,
    stateHolder: ProtectionStateHolder,
    networkMonitor: NetworkMonitor,
    ruleManager: RuleManager,
    blocklistDao: BlocklistDao,
) : ViewModel() {
    private val sources = blocklistDao.observeAll().map { list ->
        list.map {
            BlocklistSource(
                it.id, it.name, it.description, it.url,
                runCatching { BlockCategory.valueOf(it.category) }.getOrDefault(BlockCategory.ADS),
                it.enabled, it.builtIn, it.license, it.domainCount, it.sha256, it.updatedAt, it.lastError, it.sizeNote,
            )
        }
    }
    private val tick = flow {
        while (true) {
            emit(Unit)
            delay(1_000)
        }
    }

    private val base = combine(
        stateHolder.state, settings.dns, networkMonitor.status, sources, appRepo.disabledPackages,
    ) { protection, dns, net, src, disabled -> Base(protection, dns, net, src, YoutubeClassifier.APP_PACKAGE !in disabled) }

    val ui: StateFlow<YoutubeUi?> = combine(base, ruleManager.status, tick) { b, engine, _ ->
        val d = appRepo.details(YoutubeClassifier.APP_PACKAGE)
        YoutubeUi(
            installed = d != null, version = d?.versionName, versionCode = d?.versionCode ?: 0, systemApp = d?.isSystemApp ?: false,
            installer = d?.installerPackage, protection = b.protection, appFilteringEnabled = b.appEnabled, dns = b.dns, network = b.net,
            privateDns = PrivateDnsMode.read(context), privateDnsHost = PrivateDnsMode.hostname(context), engine = engine, sources = b.sources,
            rulesVersion = rulesVersion(b.sources), lastUpdate = b.sources.filter { it.url != null }.maxOfOrNull { it.updatedAt } ?: 0L,
            snapshot = diagnostics.snapshot(), entries = diagnostics.entries(),
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

    private class Base(
        val protection: ProtectionState, val dns: DnsSettings, val net: NetworkStatus,
        val sources: List<BlocklistSource>, val appEnabled: Boolean,
    )

    /** Short fingerprint of exactly which lists (and which downloaded versions) are active. */
    private fun rulesVersion(src: List<BlocklistSource>): String {
        val text = src.filter { it.enabled }.joinToString("|") { "${it.id}:${it.sha256 ?: "bundled"}" }
        return MessageDigest.getInstance("SHA-256").digest(text.toByteArray()).take(4).joinToString("") { "%02x".format(it) }
    }

    fun setProfile(p: YoutubeProfile) = viewModelScope.launch { settings.setYoutubeProfile(p) }
    fun setRecording(on: Boolean) = viewModelScope.launch { settings.setYoutubeDiagnostics(on) }
    fun setAppFiltering(on: Boolean) = viewModelScope.launch { appRepo.setFilteringEnabled(YoutubeClassifier.APP_PACKAGE, on) }
    fun clearLog() = diagnostics.clear()
    fun allow(domain: String) = viewModelScope.launch { rules.add(domain, isAllow = true) }
    fun block(domain: String) = viewModelScope.launch { rules.add(domain, isAllow = false) }

    /** Plain-text report for the user to save or share manually. Contains YouTube-related lookups only. */
    fun exportText(): String {
        val u = ui.value ?: return ""
        val fmt = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.MEDIUM)
        val sb = StringBuilder()
        sb.appendLine("AdShield YouTube diagnostics (local report, not uploaded anywhere)")
        sb.appendLine("Generated: ${fmt.format(Date())}")
        sb.appendLine("Android: ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
        sb.appendLine("YouTube app: ${if (u.installed) "${u.version} (${u.versionCode}) system=${u.systemApp} installer=${u.installer}" else "not installed"}")
        sb.appendLine("Network: ${u.network.type.label}, validated=${u.network.validated}, metered=${u.network.metered}, ipv6=${u.network.ipv6Available}")
        sb.appendLine("Private DNS: ${u.privateDns} (${u.privateDnsHost ?: "-"})  | upstream=${u.dns.upstreamMode}  | capture hard-coded resolvers=${u.dns.captureKnownResolvers}")
        sb.appendLine("YouTube profile: ${u.dns.youtubeProfile}  | protection=${u.protection::class.simpleName}  | app filtering=${u.appFilteringEnabled}")
        sb.appendLine("Rules version: ${u.rulesVersion}  | last list update: ${if (u.lastUpdate == 0L) "never" else fmt.format(Date(u.lastUpdate))}")
        u.sources.filter { it.enabled }.forEach { sb.appendLine("  list ${it.id}: ${it.domainCount} domains, sha256=${it.sha256?.take(12) ?: "bundled"}") }
        val s = u.snapshot
        sb.appendLine("Counters (this session): related lookups=${s.totalRelated}, ad-serving lookups blocked=${s.adServingBlocked}, tracker lookups blocked=${s.trackersBlocked}, playback-critical allowed=${s.allowedYoutube}, playback-critical problems=${s.playbackCriticalProblems}")
        sb.appendLine("Bypass signals: hard-coded resolver queries=${s.bypass.hardcodedResolverQueries}, refused TCP=${s.bypass.refusedTcpByPort}, dropped UDP=${s.bypass.droppedUdpByPort}")
        s.attribution?.let { sb.appendLine("Attribution: attributed=${it.attributed}, unattributed=${it.unattributed}, systemResolverMasksApps=${it.systemResolverMasksApps}") }
        sb.appendLine()
        sb.appendLine("time | verdict | class | domain | type | rule | list | via-cname | cache | app | µs")
        u.entries.forEach { e ->
            sb.appendLine("${fmt.format(Date(e.atMillis))} | ${e.verdict.name} | ${e.cls.name} | ${e.domain} | ${e.qtype} | ${e.matchedRule ?: "-"} | ${e.sourceId ?: "-"} | ${e.viaCname ?: "-"} | ${e.fromCache} | ${e.attributedPackage ?: "-"} | ${e.micros}")
        }
        return sb.toString()
    }
}

// ---------------------------------------------------------------- screen

private enum class LogFilter(val label: String) { ALL("All"), BLOCKED("Blocked"), ALLOWED("Allowed"), PROBLEMS("Problems") }

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun YoutubeScreen(onBack: (() -> Unit)?, vm: YoutubeViewModel = hiltViewModel()) {
    val ui by vm.ui.collectAsStateWithLifecycle()
    val u = ui
    var filter by remember { mutableStateOf(LogFilter.ALL) }
    var selected by remember { mutableStateOf<LogEntry?>(null) }
    val context = LocalContext.current
    val exporter = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
        if (uri != null) {
            runCatching { context.contentResolver.openOutputStream(uri)?.use { it.write(vm.exportText().toByteArray()) } }
        }
    }

    ScreenScaffold(title = "YouTube protection", onBack = onBack) { padding ->
        if (u == null) return@ScreenScaffold
        val running = u.protection is ProtectionState.Running
        LazyColumn(
            Modifier.fillMaxSize(),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = padding.calculateTopPadding() + 4.dp, bottom = padding.calculateBottomPadding() + 24.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            item { StatusPanel(u) }
            item { WarningsPanel(u) }

            item { SectionTitle("This session (real counts of DNS lookups)") }
            item {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        StatTile("YouTube-related lookups", u.snapshot.totalRelated, Modifier.weight(1f))
                        StatTile("Ad-serving lookups blocked", u.snapshot.adServingBlocked, Modifier.weight(1f), accent = Palette.Teal)
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        StatTile("Tracker lookups blocked", u.snapshot.trackersBlocked, Modifier.weight(1f), accent = Palette.Teal)
                        StatTile("Playback lookups allowed", u.snapshot.allowedYoutube, Modifier.weight(1f))
                    }
                }
            }
            item { BodyText("A blocked lookup stops one request to an ad or tracking host. It does not mean an ad was removed: the same video can still carry ads inside its own stream.") }

            item { SectionTitle("Playback compatibility") }
            item {
                val (text, color) = playbackCompatibility(u.snapshot, running)
                Panel { Row(verticalAlignment = Alignment.Top) { Text(text, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium, color = color) } }
            }

            item { SectionTitle("Filter lists") }
            item { ListsPanel(u) }

            item { SectionTitle("Profile") }
            item {
                Panel {
                    Column {
                        YoutubeProfile.entries.forEach { p ->
                            Row(
                                Modifier.fillMaxWidth().clickable(role = Role.RadioButton) { vm.setProfile(p) }.padding(vertical = 6.dp),
                                verticalAlignment = Alignment.Top,
                            ) {
                                RadioButton(u.dns.youtubeProfile == p, onClick = null, colors = RadioButtonDefaults.colors(selectedColor = Palette.Teal), modifier = Modifier.padding(top = 2.dp, end = 12.dp))
                                Column { Text(p.label, style = MaterialTheme.typography.titleMedium); BodyText(p.description) }
                            }
                        }
                        SwitchRow("Filter the YouTube app", u.appFilteringEnabled, { vm.setAppFiltering(it) }, subtitle = "Off = YouTube bypasses AdShield completely.", enabled = u.installed)
                        SwitchRow("Record the diagnostic log", u.dns.youtubeDiagnostics, { vm.setRecording(it) }, subtitle = "Keeps the last 1,500 YouTube-related lookups in memory only. Cleared when protection stops. Off by default.")
                    }
                }
            }

            item { SectionTitle("By type of host") }
            item { BreakdownPanel(u.snapshot) }

            item { SectionTitle("Which ads can DNS filtering handle?") }
            item { DeliveryPanel() }

            item { SectionTitle("Diagnostic log") }
            item {
                Panel {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        if (!u.dns.youtubeDiagnostics) BodyText("Recording is off. Turn on “Record the diagnostic log” above, then play a video.")
                        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            LogFilter.entries.forEach { f -> FilterChip(selected = filter == f, onClick = { filter = f }, label = { Text(f.label) }) }
                        }
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text("${u.entries.size} entries", Modifier.weight(1f), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            IconButton(onClick = { exporter.launch("adshield-youtube-diagnostics.txt") }, enabled = u.entries.isNotEmpty()) { Icon(Icons.Rounded.Share, "Export log") }
                            IconButton(onClick = vm::clearLog) { Icon(Icons.Rounded.Delete, "Clear log") }
                        }
                        BodyText("Export saves a text file wherever you choose. Nothing is uploaded by AdShield.")
                    }
                }
            }
            val shown = u.entries.filter {
                when (filter) {
                    LogFilter.ALL -> true
                    LogFilter.BLOCKED -> it.verdict.blocked
                    LogFilter.ALLOWED -> it.verdict.name.startsWith("ALLOWED")
                    LogFilter.PROBLEMS -> it.verdict == Verdict.FAILED || (it.verdict.blocked && it.cls.playbackCritical)
                }
            }.take(200)
            items(shown, key = { "${it.atMillis}-${it.domain}-${it.qtype}-${it.verdict}" }) { e -> LogRow(e, u) { selected = e } }
        }
    }

    val current = selected
    if (current != null && u != null) {
        val e = current
        EntryDialog(e, u, onDismiss = { selected = null }, onAllow = { vm.allow(e.domain); selected = null }, onBlock = { vm.block(e.domain); selected = null })
    }
}

@Composable
private fun StatusPanel(u: YoutubeUi) {
    Panel {
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(u.status.headline, style = MaterialTheme.typography.titleLarge, color = if (u.status == YoutubeStatus.ACTIVE_LIMITED) Palette.Teal else MaterialTheme.colorScheme.onSurface)
            BodyText("AdShield filters separate ad and tracking domains. Ads delivered inside the video stream cannot be removed by DNS filtering, and this app has not been verified to remove YouTube ads.")
            InfoRow("YouTube app", if (u.installed) "${u.version ?: "?"} (${u.versionCode})" else "Not installed")
            if (u.installed) InfoRow("Source", (if (u.systemApp) "Preinstalled / system-updated" else "User-installed") + (u.installer?.let { " · $it" } ?: ""))
            InfoRow("VPN", if (u.protection is ProtectionState.Running) "Active (local, DNS only)" else "Inactive")
            InfoRow("DNS filtering", if (u.engine.loaded) "${formatCount(u.engine.domainCount.toLong())} domains loaded" else "Rules not loaded")
            InfoRow("Profile", u.dns.youtubeProfile.label)
            InfoRow("Network", u.network.type.label + if (u.network.ipv6Available) " · IPv6" else "")
        }
    }
}

@Composable
private fun WarningsPanel(u: YoutubeUi) {
    val s = u.snapshot
    val running = u.protection is ProtectionState.Running
    val items = buildList<Pair<String, Color>> {
        if (u.privateDns == PrivateDnsMode.Mode.STRICT) {
            add(
                "Android's Private DNS is set to ${u.privateDnsHost ?: "a specific provider"}. Depending on the Android version this can make DNS " +
                    "go straight to that provider and bypass AdShield. The counters above tell you which is happening: if YouTube-related lookups " +
                    "are being counted, AdShield is seeing them; if they stay at 0 while you use YouTube, it is bypassed. Any blocking you notice " +
                    "may then come from that provider, not from AdShield." to Palette.Warning,
            )
        }
        if (!u.dns.captureKnownResolvers) add("Capture of hard-coded resolvers is off: an app using its own plain DNS server (for example 8.8.8.8) bypasses AdShield." to Palette.Warning)
        if (s.bypass.hardcodedResolverQueries > 0) add("${s.bypass.hardcodedResolverQueries} lookup(s) were sent by apps to a hard-coded public resolver. They were captured and filtered." to Palette.TextSecondary)
        if (s.bypass.encryptedDnsAttempts > 0) add("Possible DNS bypass: apps tried encrypted DNS to a known public resolver ${s.bypass.encryptedDnsAttempts} time(s) (refused; they should fall back to filtered DNS). Resolvers AdShield does not know cannot be detected." to Palette.Warning)
        s.attribution?.let { if (it.systemResolverMasksApps) add("Android's system resolver performs DNS for apps, so lookups cannot be tied to YouTube by app. Lookups are matched to YouTube by host name instead." to Palette.TextSecondary) }
        if (running && s.totalRelated == 0L) add("No YouTube-related lookups seen yet. If you have been playing videos, YouTube may be resolving names outside AdShield (Private DNS, encrypted DNS, or app excluded)." to Palette.TextSecondary)
        if (u.network.type == com.adshield.domain.model.ConnectionType.NONE) add("No network connection." to Palette.Warning)
    }
    if (items.isEmpty()) return
    Panel {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Notices", style = MaterialTheme.typography.titleMedium)
            items.forEach { (text, color) -> Text("•  $text", style = MaterialTheme.typography.bodyMedium, color = color) }
        }
    }
}

@Composable
private fun ListsPanel(u: YoutubeUi) {
    val fmt = remember { DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT) }
    Panel {
        Column {
            InfoRow("Rules version", u.rulesVersion)
            InfoRow("Last successful list update", if (u.lastUpdate == 0L) "Never (bundled lists only)" else fmt.format(Date(u.lastUpdate)))
            u.sources.filter { it.enabled }.forEach { src ->
                InfoRow(src.name, "${formatCount(src.domainCount.toLong())}" + (src.sha256?.let { " · ${it.take(8)}" } ?: " · bundled"))
            }
            BodyText("The rules version is a fingerprint of which lists, and which downloaded copies, are active. Quote it when comparing results.")
        }
    }
}

@Composable
private fun BreakdownPanel(s: DiagnosticsSnapshot) {
    Panel {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            val rows = YoutubeClass.entries.filter { it != YoutubeClass.OTHER }
            var any = false
            rows.forEach { c ->
                val m = s.counts[c] ?: return@forEach
                any = true
                val blocked = m.filterKeys { it.blocked }.values.sum()
                val allowed = m.filterKeys { it.name.startsWith("ALLOWED") }.values.sum()
                val failed = m[Verdict.FAILED] ?: 0
                Column {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(c.label, Modifier.weight(1f), style = MaterialTheme.typography.titleMedium)
                        Text("blocked ${formatCount(blocked)} · allowed ${formatCount(allowed)}" + if (failed > 0) " · failed $failed" else "", style = MaterialTheme.typography.bodySmall)
                    }
                    BodyText(c.explanation)
                    if (c.mayCarrySameOriginAds) Pill("May carry ads DNS cannot separate", Palette.Warning, Modifier.padding(top = 4.dp))
                }
            }
            if (!any) BodyText("No YouTube-related lookups observed yet.")
        }
    }
}

@Composable
private fun DeliveryPanel() {
    Panel {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            DeliveryRow("Separate third-party ad domains", "DNS can block", "For example doubleclick.net, googlesyndication.com. Safe to block; included in the lists.", Palette.Teal)
            DeliveryRow("Independent ad and measurement requests", "DNS can block when the host is separate", "Blocking the host stops the request but some players wait for it. Listed hosts only, no keyword guessing.", Palette.Teal)
            DeliveryRow("Tracking and analytics", "DNS can block", "Usually safe. Hosts that carry watch history or playback state are deliberately not blocked.", Palette.Teal)
            DeliveryRow("YouTube first-party ad infrastructure", "DNS cannot separate", "Ad placements are returned by the same player API host as the video information. Blocking it breaks playback.", Palette.Warning)
            DeliveryRow("Server-side ad insertion", "DNS cannot separate", "The ad is stitched into the video stream before it reaches the phone.", Palette.Warning)
            DeliveryRow("Ads served with the video", "DNS cannot separate", "They come from the same video delivery hosts as content. Blocking these hosts blocks the video.", Palette.Warning)
            DeliveryRow("Creator sponsorships", "Not a network ad", "Part of the video itself.", Palette.TextSecondary)
        }
    }
}

@Composable
private fun DeliveryRow(title: String, verdict: String, detail: String, color: Color) {
    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(title, Modifier.weight(1f), style = MaterialTheme.typography.titleMedium)
            Pill(verdict, color)
        }
        BodyText(detail)
    }
}

@Composable
private fun LogRow(e: LogEntry, u: YoutubeUi, onClick: () -> Unit) {
    val time = remember(e.atMillis) { DateFormat.getTimeInstance(DateFormat.MEDIUM).format(Date(e.atMillis)) }
    Panel(onClick = onClick) {
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(e.domain, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium, maxLines = 1)
                Spacer(Modifier.width(8.dp))
                Pill(if (e.verdict.blocked) "Blocked" else if (e.verdict == Verdict.FAILED) "Failed" else "Allowed", if (e.verdict.blocked) Palette.Teal else if (e.verdict == Verdict.FAILED) Palette.Warning else Palette.TextSecondary)
            }
            Text("$time · ${e.cls.label}${if (e.fromCache) " · cached" else ""}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(ruleText(e, u), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

private fun ruleText(e: LogEntry, u: YoutubeUi): String {
    val list = e.sourceId?.let { id -> u.sources.firstOrNull { it.id == id }?.name ?: id }
    return when {
        e.verdict.blocked && e.viaCname != null -> "Blocked: alias target ${e.viaCname} matched “${e.matchedRule}”" + (list?.let { " ($it)" } ?: "")
        e.verdict.blocked -> "Blocked by rule “${e.matchedRule}”" + (list?.let { " in $it" } ?: " (your custom rule)")
        else -> e.verdict.label
    }
}

@Composable
private fun EntryDialog(e: LogEntry, u: YoutubeUi, onDismiss: () -> Unit, onAllow: () -> Unit, onBlock: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(e.domain, style = MaterialTheme.typography.titleMedium) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                InfoRow("Decision", e.verdict.label)
                InfoRow("Reason", ruleText(e, u))
                InfoRow("Host type", e.cls.label)
                if (e.cnames.isNotEmpty()) InfoRow("Aliases (CNAME)", e.cnames.joinToString(" → "))
                InfoRow("Answered from", if (e.fromCache) "AdShield's cache" else "Upstream / local filter")
                InfoRow("Record type", e.qtype.toString())
                InfoRow("Time spent", "${e.micros} µs")
                InfoRow("Attributed app", e.attributedPackage ?: "Not available")
                BodyText(e.cls.explanation)
                if (e.verdict.blocked && e.cls.playbackCritical) BodyText("This host type is playback-critical. If playback broke, allowing it is justified; note that doing so can let related ads through.", color = Palette.Warning)
            }
        },
        confirmButton = { TextButton(onClick = onAllow) { Text("Always allow") } },
        dismissButton = {
            Row {
                OutlinedButton(onClick = onBlock) { Text("Always block") }
                TextButton(onClick = onDismiss) { Text("Close") }
            }
        },
    )
}
