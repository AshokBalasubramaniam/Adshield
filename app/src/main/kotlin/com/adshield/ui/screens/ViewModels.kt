package com.adshield.ui.screens

import android.content.Context
import android.os.Process
import android.os.SystemClock
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adshield.data.repo.AddRuleResult
import com.adshield.data.repo.AppRepository
import com.adshield.data.repo.NetworkMonitor
import com.adshield.data.repo.PrivateDnsMode
import com.adshield.data.repo.ProtectionStateHolder
import com.adshield.data.repo.RecentBlock
import com.adshield.data.repo.StatsRepository
import com.adshield.data.repo.UserRuleRepository
import com.adshield.data.db.BlocklistDao
import com.adshield.data.rules.DownloadResult
import com.adshield.data.rules.RuleManager
import com.adshield.data.settings.DnsSettings
import com.adshield.data.settings.SettingsRepository
import com.adshield.domain.model.AppStat
import com.adshield.domain.model.BlockCategory
import com.adshield.domain.model.BlockMode
import com.adshield.domain.model.BlocklistSource
import com.adshield.domain.model.DayStat
import com.adshield.domain.model.EngineStatus
import com.adshield.domain.model.InstalledApp
import com.adshield.domain.model.NetworkStatus
import com.adshield.domain.model.ProtectionState
import com.adshield.domain.model.StatsTotals
import com.adshield.domain.model.UpstreamMode
import com.adshield.domain.model.UserRule
import com.adshield.dns.DohDnsUpstream
import com.adshield.engine.IpLiteral
import com.adshield.vpn.ProtectionController
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

// ---------- Main / onboarding ----------

@HiltViewModel
class MainViewModel @Inject constructor(settings: SettingsRepository) : ViewModel() {
    /** null while loading (keeps the splash screen up), then true/false. */
    val onboardingDone: StateFlow<Boolean?> =
        settings.onboardingDone.map<Boolean, Boolean?> { it }.stateIn(viewModelScope, SharingStarted.Eagerly, null)
}

sealed interface ListDownloadUi {
    data object Idle : ListDownloadUi
    data object Running : ListDownloadUi
    data class Done(val ok: Int, val failed: Int) : ListDownloadUi
}

@HiltViewModel
class OnboardingViewModel @Inject constructor(
    private val settings: SettingsRepository,
    private val rules: RuleManager,
) : ViewModel() {
    private val _download = MutableStateFlow<ListDownloadUi>(ListDownloadUi.Idle)
    val download: StateFlow<ListDownloadUi> = _download.asStateFlow()

    fun downloadLists() {
        if (_download.value == ListDownloadUi.Running) return
        _download.value = ListDownloadUi.Running
        viewModelScope.launch {
            val outcomes = rules.updateAll(force = true)
            _download.value = ListDownloadUi.Done(
                ok = outcomes.count { it.result is DownloadResult.Success },
                failed = outcomes.count { it.result is DownloadResult.Failure },
            )
        }
    }

    fun finish(onDone: () -> Unit) {
        viewModelScope.launch {
            settings.setOnboardingDone(true)
            onDone()
        }
    }
}

// ---------- Dashboard ----------

enum class LoadLevel(val label: String) { IDLE("Idle"), LOW("Low"), MODERATE("Moderate"), HIGH("High") }

data class ServiceLoad(val cpuPercent: Float = 0f, val queriesPerMinute: Int = 0, val level: LoadLevel = LoadLevel.IDLE)

@HiltViewModel
class DashboardViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
    private val controller: ProtectionController,
    stateHolder: ProtectionStateHolder,
    private val statsRepo: StatsRepository,
    networkMonitor: NetworkMonitor,
    ruleManager: RuleManager,
) : ViewModel() {
    val protection: StateFlow<ProtectionState> = stateHolder.state
    val totals: StateFlow<StatsTotals> = statsRepo.totals.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), StatsTotals())
    val network: StateFlow<NetworkStatus> = networkMonitor.status.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), NetworkStatus())
    val engine: StateFlow<EngineStatus> = ruleManager.status
    val privateDns: PrivateDnsMode.Mode get() = PrivateDnsMode.read(context)
    val privateDnsHost: String? get() = PrivateDnsMode.hostname(context)

    val load: StateFlow<ServiceLoad> = flow {
        var lastCpu = Process.getElapsedCpuTime()
        var lastWall = SystemClock.elapsedRealtime()
        var lastQueries = totals.value.totalQueries
        while (true) {
            delay(LOAD_INTERVAL_MS)
            val cpu = Process.getElapsedCpuTime()
            val wall = SystemClock.elapsedRealtime()
            val queries = totals.value.totalQueries
            val dWall = (wall - lastWall).coerceAtLeast(1)
            val pct = (cpu - lastCpu) * 100f / dWall
            val qpm = ((queries - lastQueries).coerceAtLeast(0) * 60_000L / dWall).toInt()
            lastCpu = cpu; lastWall = wall; lastQueries = queries
            val running = protection.value is ProtectionState.Running
            emit(
                ServiceLoad(
                    pct, qpm,
                    when {
                        !running -> LoadLevel.IDLE
                        pct < 1.5f -> LoadLevel.LOW
                        pct < 5f -> LoadLevel.MODERATE
                        else -> LoadLevel.HIGH
                    },
                ),
            )
        }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), ServiceLoad())

    fun consentIntent() = controller.consentIntent()
    fun start() = controller.start()
    fun stop() = controller.stop()

    private companion object {
        const val LOAD_INTERVAL_MS = 5_000L
    }
}

// ---------- Apps ----------

data class AppRow(val app: InstalledApp, val total: Long, val blocked: Long)

@HiltViewModel
class AppsViewModel @Inject constructor(
    private val appRepo: AppRepository,
    private val rules: UserRuleRepository,
    statsRepo: StatsRepository,
) : ViewModel() {
    private val allApps = MutableStateFlow<List<InstalledApp>>(emptyList())
    private val _loading = MutableStateFlow(true)
    val loading: StateFlow<Boolean> = _loading.asStateFlow()
    val query = MutableStateFlow("")
    private val _selected = MutableStateFlow<String?>(null)
    val selected: StateFlow<String?> = _selected.asStateFlow()

    private val stats = statsRepo.topApps(1000)

    val rows: StateFlow<List<AppRow>> = combine(allApps, appRepo.disabledPackages, query, stats) { apps, disabled, q, s ->
        val byPkg = s.associateBy { it.packageName }
        apps.asSequence()
            .map { it.copy(filteringEnabled = it.packageName !in disabled) }
            .filter { q.isBlank() || it.label.contains(q, ignoreCase = true) || it.packageName.contains(q, ignoreCase = true) }
            .map { AppRow(it, byPkg[it.packageName]?.total ?: 0, byPkg[it.packageName]?.blocked ?: 0) }
            .toList()
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val appRules: StateFlow<List<UserRule>> = combine(rules.rules, _selected) { all, pkg ->
        all.filter { it.isAllow && pkg != null && it.packageName == pkg }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val disabledCount: StateFlow<Int> = appRepo.disabledPackages.map { it.size }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), 0)

    init { refresh() }

    fun refresh() {
        viewModelScope.launch {
            _loading.value = true
            allApps.value = appRepo.launchableApps()
            _loading.value = false
        }
    }

    fun installed(packages: List<String>): List<String> = packages.filter { appRepo.isInstalled(it) }
    fun setEnabled(pkg: String, enabled: Boolean) = viewModelScope.launch { appRepo.setFilteringEnabled(pkg, enabled) }
    fun enableAll() = viewModelScope.launch { appRepo.enableAll() }
    fun select(pkg: String?) { _selected.value = pkg }
    fun labelOf(pkg: String) = appRepo.labelOf(pkg)

    suspend fun addAllow(domain: String): AddRuleResult {
        val pkg = _selected.value ?: return AddRuleResult.INVALID
        return rules.add(domain, isAllow = true, packageName = pkg)
    }

    fun removeRule(id: Long) = viewModelScope.launch { rules.remove(id) }
}

// ---------- Blocklists ----------

@HiltViewModel
class BlocklistsViewModel @Inject constructor(
    dao: BlocklistDao,
    private val rules: RuleManager,
    private val blocklistDao: BlocklistDao,
    private val settings: SettingsRepository,
) : ViewModel() {
    val sources: StateFlow<List<BlocklistSource>> = dao.observeAll().map { list ->
        list.map {
            BlocklistSource(
                it.id, it.name, it.description, it.url,
                runCatching { BlockCategory.valueOf(it.category) }.getOrDefault(BlockCategory.ADS),
                it.enabled, it.builtIn, it.license, it.domainCount, it.sha256, it.updatedAt, it.lastError, it.sizeNote,
            )
        }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val engine: StateFlow<EngineStatus> = rules.status
    val autoUpdate: StateFlow<Boolean> = settings.autoUpdateLists.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), true)
    private val _busy = MutableStateFlow<Set<String>>(emptySet())
    val busy: StateFlow<Set<String>> = _busy.asStateFlow()
    private val _message = MutableStateFlow<String?>(null)
    val message: StateFlow<String?> = _message.asStateFlow()

    fun clearMessage() { _message.value = null }

    fun setEnabled(id: String, enabled: Boolean) = viewModelScope.launch { blocklistDao.setEnabled(id, enabled) }

    fun update(id: String) = viewModelScope.launch {
        _busy.update { it + id }
        val result = rules.updateOne(id)?.result
        _busy.update { it - id }
        _message.value = when (result) {
            is DownloadResult.Success -> "Updated · ${formatNum(result.domainCount)} domains"
            is DownloadResult.Failure -> "Update failed: ${result.reason}"
            null -> null
        }
    }

    fun updateAll() = viewModelScope.launch {
        _busy.update { it + ALL }
        val outcomes = rules.updateAll(force = true)
        _busy.update { it - ALL }
        val ok = outcomes.count { it.result is DownloadResult.Success }
        val failed = outcomes.count { it.result is DownloadResult.Failure }
        _message.value = "Updated $ok list(s)" + if (failed > 0) ", $failed failed (see list details)" else ""
    }

    fun addCustom(name: String, url: String, category: BlockCategory, onResult: (String?) -> Unit) = viewModelScope.launch {
        _busy.update { it + ALL }
        val error = rules.addCustomList(name, url, category)
        _busy.update { it - ALL }
        onResult(error)
    }

    fun remove(id: String) = viewModelScope.launch { rules.removeCustomList(id) }

    fun setAutoUpdate(enabled: Boolean) = viewModelScope.launch { settings.setAutoUpdateLists(enabled) }

    private fun formatNum(n: Int) = java.text.NumberFormat.getIntegerInstance().format(n)

    companion object {
        const val ALL = "*all*"
    }
}

// ---------- Allow / block rules ----------

@HiltViewModel
class RulesViewModel @Inject constructor(private val repo: UserRuleRepository, private val apps: AppRepository) : ViewModel() {
    val rules: StateFlow<List<UserRule>> = repo.rules.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())
    suspend fun add(domain: String, isAllow: Boolean): AddRuleResult = repo.add(domain, isAllow)
    fun remove(id: Long) = viewModelScope.launch { repo.remove(id) }
    fun labelOf(pkg: String) = apps.labelOf(pkg)
}

// ---------- DNS settings ----------

@HiltViewModel
class DnsSettingsViewModel @Inject constructor(
    private val settings: SettingsRepository,
    private val protectionHolder: ProtectionStateHolder,
) : ViewModel() {
    val dns: StateFlow<DnsSettings> = settings.dns.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), DnsSettings())
    val running: StateFlow<Boolean> = protectionHolder.state.map { it is ProtectionState.Running }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    fun setBlockMode(m: BlockMode) = viewModelScope.launch { settings.setBlockMode(m) }
    fun setUpstreamMode(m: UpstreamMode) = viewModelScope.launch { settings.setUpstreamMode(m) }
    fun setCapture(v: Boolean) = viewModelScope.launch { settings.setCaptureKnownResolvers(v) }
    fun setProtectStreaming(v: Boolean) = viewModelScope.launch { settings.setProtectStreamingFirstParty(v) }
    fun setAttribute(v: Boolean) = viewModelScope.launch { settings.setAttributeQueries(v) }

    /** Returns an error message or null when saved. */
    suspend fun saveCustomUpstream(text: String): String? {
        if (IpLiteral.parseList(text) == null) return "Enter 1–4 IPv4/IPv6 addresses (not host names), separated by commas"
        settings.setCustomUpstream(text)
        return null
    }

    suspend fun saveDohUrl(url: String): String? {
        if (!DohDnsUpstream.isValid(url)) return "Enter a valid https:// URL"
        settings.setDohUrl(url)
        return null
    }
}

// ---------- Stats ----------

data class AppStatRow(val packageName: String, val label: String, val total: Long, val blocked: Long)

@HiltViewModel
class StatsViewModel @Inject constructor(
    private val statsRepo: StatsRepository,
    private val apps: AppRepository,
    private val diagnostics: com.adshield.youtube.YoutubeDiagnostics,
) : ViewModel() {
    val totals: StateFlow<StatsTotals> = statsRepo.totals.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), StatsTotals())
    val days: StateFlow<List<DayStat>> = statsRepo.lastDays(7).stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())
    val recent: StateFlow<List<RecentBlock>> = statsRepo.recentBlocks
    val topApps: StateFlow<List<AppStatRow>> = statsRepo.topApps(10).map { list: List<AppStat> ->
        list.map { AppStatRow(it.packageName, if (it.packageName.isEmpty()) "" else apps.labelOf(it.packageName), it.total, it.blocked) }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    fun reset() = viewModelScope.launch {
        statsRepo.reset()
        diagnostics.clear()
    }
}

// ---------- Network ----------

@HiltViewModel
class NetworkViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
    networkMonitor: NetworkMonitor,
    stateHolder: ProtectionStateHolder,
    settings: SettingsRepository,
) : ViewModel() {
    val network: StateFlow<NetworkStatus> = networkMonitor.status.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), NetworkStatus())
    val protection: StateFlow<ProtectionState> = stateHolder.state
    val dns: StateFlow<DnsSettings> = settings.dns.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), DnsSettings())
    val privateDns: PrivateDnsMode.Mode get() = PrivateDnsMode.read(context)
}
