package com.adshield.vpn

import android.app.PendingIntent
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.BatteryManager
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import com.adshield.MainActivity
import com.adshield.R
import com.adshield.data.repo.AppRepository
import com.adshield.data.repo.NetworkMonitor
import com.adshield.data.repo.ProtectionStateHolder
import com.adshield.data.repo.StatsRepository
import com.adshield.data.repo.Underlying
import com.adshield.data.rules.RuleManager
import com.adshield.data.settings.DnsSettings
import com.adshield.data.settings.SettingsRepository
import com.adshield.dns.DnsCache
import com.adshield.dns.DnsQueryProcessor
import com.adshield.dns.DnsUpstream
import com.adshield.domain.model.ProtectionState
import com.adshield.engine.AdFilteringEngine
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.sample
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import javax.inject.Inject

/**
 * Local DNS-filtering VPN.
 *
 * The tunnel routes **only** DNS traffic (the virtual DNS addresses, plus optionally well-known public
 * resolvers). All other traffic bypasses the tunnel entirely: no browsing traffic is read, proxied or
 * relayed, and nothing leaves the device towards an AdShield-operated server.
 */
@AndroidEntryPoint
class AdShieldVpnService : VpnService() {
    @Inject lateinit var engine: AdFilteringEngine
    @Inject lateinit var dnsCache: DnsCache
    @Inject lateinit var ruleManager: RuleManager
    @Inject lateinit var statsRepo: StatsRepository
    @Inject lateinit var settings: SettingsRepository
    @Inject lateinit var appRepo: AppRepository
    @Inject lateinit var networkMonitor: NetworkMonitor
    @Inject lateinit var stateHolder: ProtectionStateHolder

    private val scope = CoroutineScope(
        SupervisorJob() + Dispatchers.Default + CoroutineExceptionHandler { _, e -> Log.e(TAG, "Unhandled", e) },
    )
    private var protectionJob: Job? = null
    private lateinit var notifier: VpnNotifier

    @Volatile private var upstream: DnsUpstream? = null
    @Volatile private var dnsSettings = DnsSettings()
    @Volatile private var underlying: Underlying? = null

    private data class TunnelConfig(val disabledApps: Set<String>, val captureResolvers: Boolean)

    override fun onCreate() {
        super.onCreate()
        notifier = VpnNotifier(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == VpnConfig.ACTION_STOP) {
            stopProtection()
            return START_NOT_STICKY
        }
        // A foreground service must call startForeground promptly after startForegroundService().
        enterForeground(getString(R.string.notification_starting))
        if (protectionJob?.isActive == true) return START_STICKY

        val systemRestart = intent == null
        protectionJob = scope.launch {
            if (systemRestart && !settings.protectionDesiredNow()) {
                shutdown()
                return@launch
            }
            if (prepare(this@AdShieldVpnService) != null) {
                fail("VPN permission is missing. Open AdShield and turn protection on again.", clearDesired = true)
                return@launch
            }
            runProtection()
        }
        return START_STICKY
    }

    private fun enterForeground(text: String) {
        val notification = notifier.build(text)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(VpnConfig.NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(VpnConfig.NOTIFICATION_ID, notification)
        }
    }

    // region protection lifecycle

    private suspend fun runProtection() {
        stateHolder.set(ProtectionState.Starting("Loading filter rules"))
        try {
            ruleManager.reload()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            fail("Could not load filter rules: ${e.message}")
            return
        }
        settings.setProtectionDesired(true)

        val processor = DnsQueryProcessor(
            engine = engine,
            cache = dnsCache,
            upstream = { upstream },
            blockMode = { dnsSettings.blockMode },
            sink = statsRepo,
        )
        val uidResolver = AppUidResolver(this) { dnsSettings.attributeQueriesToApps }
        val loop = TunnelLoop(processor) { uidResolver.resolve(it) }

        kotlinx.coroutines.supervisorScope {
            launchGuarded { settings.dns.collect { dnsSettings = it; rebuildUpstream() } }
            launchGuarded { ruleManager.changes().drop(1).collect { runCatching { ruleManager.reload() } } }
            launchGuarded { networkMonitor.underlying.collect { onNetworkChanged(it) } }
            launchGuarded { statsLoop() }
            launchGuarded { notificationLoop() }
            launchGuarded { listRefreshLoop() }

            val configs = combine(
                appRepo.disabledPackages,
                settings.dns.map { it.captureKnownResolvers }.distinctUntilChanged(),
            ) { disabled, capture -> TunnelConfig(disabled, capture) }.distinctUntilChanged()

            configs.collectLatest { runTunnel(it, loop) }
        }
    }

    private suspend fun runTunnel(cfg: TunnelConfig, loop: TunnelLoop) {
        var failures = 0
        while (currentCoroutineContext().isActive) {
            val pfd = try {
                establishInterface(cfg)
            } catch (e: Exception) {
                Log.e(TAG, "establish failed", e)
                null
            }
            if (pfd == null) {
                fail("Could not create the VPN interface. VPN permission may have been revoked.", clearDesired = true)
                return
            }
            underlying?.let { applyUnderlying(it) }
            dnsCache.clear() // never serve answers resolved before the interface (re)started
            stateHolder.set(ProtectionState.Running) // only now is packet processing actually live
            enterForeground(getString(R.string.notification_active))
            val startedAt = SystemClock.elapsedRealtime()
            try {
                loop.run(pfd)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "tunnel loop failed", e)
            }
            currentCoroutineContext().ensureActive()
            // The interface died without us asking: recover with exponential backoff.
            if (SystemClock.elapsedRealtime() - startedAt > STABLE_MS) failures = 0
            failures++
            if (failures > MAX_RECOVERY_ATTEMPTS) {
                fail("The VPN interface was lost repeatedly. Turn protection on again.")
                return
            }
            stateHolder.set(ProtectionState.Starting("Recovering connection"))
            delay(minOf(30_000L, 1_000L shl (failures - 1)))
        }
    }

    private fun establishInterface(cfg: TunnelConfig): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession(VpnConfig.SESSION_NAME)
            .setMtu(VpnConfig.MTU)
            .setBlocking(true)
            .setMetered(false)
            .addAddress(VpnConfig.V4_ADDRESS, 32)
            .addAddress(VpnConfig.V6_ADDRESS, 128)
            .addDnsServer(VpnConfig.V4_DNS)
            .addDnsServer(VpnConfig.V6_DNS)
            .addRoute(VpnConfig.V4_DNS, 32)
            .addRoute(VpnConfig.V6_DNS, 128)
            .setConfigureIntent(
                PendingIntent.getActivity(
                    this, 0, Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                ),
            )
        if (cfg.captureResolvers) {
            VpnConfig.KNOWN_RESOLVERS_V4.forEach { builder.addRoute(it, 32) }
            VpnConfig.KNOWN_RESOLVERS_V6.forEach { builder.addRoute(it, 128) }
        }
        // AdShield's own traffic (list downloads, upstream DNS) must never enter its own tunnel.
        runCatching { builder.addDisallowedApplication(packageName) }
        // Apps the user excluded bypass the VPN completely (their DNS is not filtered).
        cfg.disabledApps.forEach { pkg -> runCatching { builder.addDisallowedApplication(pkg) } }
        return builder.establish()
    }

    // endregion

    // region network & background loops

    private fun onNetworkChanged(u: Underlying) {
        val previous = underlying?.network
        underlying = u
        if (previous != u.network) dnsCache.clear()
        rebuildUpstream()
        applyUnderlying(u)
    }

    private fun rebuildUpstream() {
        upstream = underlying?.let { UpstreamFactory.create(dnsSettings, it) }
    }

    private fun applyUnderlying(u: Underlying) {
        runCatching { setUnderlyingNetworks(u.network?.let { arrayOf(it) }) }
    }

    private suspend fun statsLoop() {
        runCatching { statsRepo.pruneOld() }
        try {
            while (true) {
                delay(STATS_FLUSH_MS)
                runCatching { statsRepo.flush() }
            }
        } finally {
            withContext(NonCancellable) { runCatching { statsRepo.flush() } }
        }
    }

    /**
     * Refreshes stale filter lists while protection is on. Runs inside the already-alive service, so it needs
     * no WorkManager, wake lock or boot receiver. It only downloads on an unmetered, validated network with
     * a battery that is not low, and `updateAll(force = false)` skips lists refreshed within the last 12 hours.
     */
    private suspend fun listRefreshLoop() {
        while (true) {
            if (settings.autoUpdateLists.first() && networkAllowsRefresh() && !batteryLow()) {
                runCatching { ruleManager.updateAll(force = false) }
            }
            delay(REFRESH_CHECK_MS)
        }
    }

    private fun networkAllowsRefresh(): Boolean = underlying?.status?.let { it.validated && !it.metered } ?: false

    private fun batteryLow(): Boolean {
        val i = registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED)) ?: return false
        val level = i.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
        val scale = i.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
        val charging = i.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0) != 0
        return !charging && level >= 0 && scale > 0 && level * 100 / scale < LOW_BATTERY_PERCENT
    }

    @OptIn(FlowPreview::class)
    private suspend fun notificationLoop() {
        statsRepo.totals.sample(NOTIFICATION_MS).collect { totals ->
            if (stateHolder.state.value is ProtectionState.Running) {
                notifier.update(getString(R.string.notification_blocked, totals.blocked))
            }
        }
    }

    private fun CoroutineScope.launchGuarded(block: suspend () -> Unit) = launch {
        try {
            block()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "background task failed", e)
        }
    }

    // endregion

    // region stopping

    private suspend fun fail(message: String, clearDesired: Boolean = false) {
        Log.w(TAG, message)
        stateHolder.set(ProtectionState.Error(message))
        if (clearDesired) settings.setProtectionDesired(false)
        shutdown(keepState = true)
    }

    /** Stops foreground mode and the service. Does not wait for [protectionJob]; callers are on it or cancel it. */
    private fun shutdown(keepState: Boolean = false) {
        if (!keepState) stateHolder.set(ProtectionState.Stopped)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun stopProtection() {
        val job = protectionJob
        protectionJob = null
        scope.launch {
            // 1. stop packet processing and 2. close VPN resources (closing happens in TunnelLoop's finally)
            withTimeoutOrNull(STOP_TIMEOUT_MS) { job?.cancelAndJoin() }
            runCatching { statsRepo.flush() }
            statsRepo.clearRecent()
            settings.setProtectionDesired(false)
            // 3. stop the foreground service and 4. update dashboard state
            shutdown()
        }
    }

    override fun onRevoke() {
        // Another VPN took over, or the user revoked permission in system settings.
        scope.launch {
            withTimeoutOrNull(STOP_TIMEOUT_MS) { protectionJob?.cancelAndJoin() }
            protectionJob = null
            fail("VPN permission was revoked (another VPN app may have started).", clearDesired = true)
        }
    }

    override fun onDestroy() {
        scope.coroutineContext[Job]?.cancel()
        if (stateHolder.state.value !is ProtectionState.Error) stateHolder.set(ProtectionState.Stopped)
        super.onDestroy()
    }

    // endregion

    private companion object {
        const val TAG = "AdShieldVpn"
        const val STATS_FLUSH_MS = 2_000L
        const val NOTIFICATION_MS = 15_000L
        const val STABLE_MS = 60_000L
        const val STOP_TIMEOUT_MS = 3_000L
        const val REFRESH_CHECK_MS = 6L * 60 * 60 * 1000
        const val LOW_BATTERY_PERCENT = 20
        const val MAX_RECOVERY_ATTEMPTS = 6
    }
}
