package com.adshield.ui.screens

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.Block
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material.icons.rounded.Wifi
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adshield.data.repo.PrivateDnsMode
import com.adshield.domain.model.ConnectionType
import com.adshield.domain.model.ProtectionState
import com.adshield.ui.components.BodyText
import com.adshield.ui.components.IconBadge
import com.adshield.ui.components.InfoRow
import com.adshield.ui.components.Panel
import com.adshield.ui.components.Pill
import com.adshield.ui.components.PowerButton
import com.adshield.ui.components.PowerVisual
import com.adshield.ui.components.ScreenScaffold
import com.adshield.ui.components.SectionTitle
import com.adshield.ui.components.StatTile
import com.adshield.ui.components.formatCount
import com.adshield.ui.theme.Palette
import java.text.DateFormat
import java.util.Date

@Composable
fun DashboardScreen(
    onOpenApps: () -> Unit,
    onOpenLists: () -> Unit,
    onOpenNetwork: () -> Unit,
    onOpenBattery: () -> Unit,
    vm: DashboardViewModel = hiltViewModel(),
) {
    val context = LocalContext.current
    val protection by vm.protection.collectAsStateWithLifecycle()
    val totals by vm.totals.collectAsStateWithLifecycle()
    val network by vm.network.collectAsStateWithLifecycle()
    val engine by vm.engine.collectAsStateWithLifecycle()
    val load by vm.load.collectAsStateWithLifecycle()

    val consentLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) vm.start()
    }
    fun requestVpnThenStart() {
        val consent = vm.consentIntent()
        if (consent != null) consentLauncher.launch(consent) else vm.start()
    }
    val notificationLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        // Proceed either way: the notification is informational, the service does not need it to run.
        requestVpnThenStart()
    }

    fun onPowerClick() {
        when (protection) {
            is ProtectionState.Running, is ProtectionState.Starting -> vm.stop()
            else -> {
                val needsNotificationPermission = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                    ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
                if (needsNotificationPermission) notificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS) else requestVpnThenStart()
            }
        }
    }

    val visual = when (protection) {
        is ProtectionState.Running -> PowerVisual.ON
        is ProtectionState.Starting -> PowerVisual.STARTING
        is ProtectionState.Error -> PowerVisual.ERROR
        is ProtectionState.Stopped -> PowerVisual.OFF
    }

    ScreenScaffold(title = "AdShield") { padding ->
        LazyColumn(
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = padding.calculateTopPadding() + 8.dp, bottom = padding.calculateBottomPadding() + 24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                    PowerButton(visual, onClick = ::onPowerClick)
                    Spacer(Modifier.height(12.dp))
                    Text(
                        when (val p = protection) {
                            is ProtectionState.Running -> "Protected"
                            is ProtectionState.Starting -> p.detail
                            is ProtectionState.Error -> "Protection stopped"
                            is ProtectionState.Stopped -> "Not protected"
                        },
                        style = MaterialTheme.typography.headlineMedium,
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        when (protection) {
                            is ProtectionState.Running -> "DNS lookups are filtered on this device"
                            is ProtectionState.Starting -> "Setting up the local VPN"
                            is ProtectionState.Error -> "Tap the button to try again"
                            is ProtectionState.Stopped -> "Tap to turn protection on"
                        },
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                    )
                }
            }

            (protection as? ProtectionState.Error)?.let { err ->
                item {
                    Panel {
                        Row(verticalAlignment = Alignment.Top, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            Icon(Icons.Rounded.Warning, null, tint = Palette.Danger)
                            Column { Text("Could not keep protection running", style = MaterialTheme.typography.titleMedium); BodyText(err.message) }
                        }
                    }
                }
            }

            if (protection is ProtectionState.Running && vm.privateDns == PrivateDnsMode.Mode.STRICT) {
                item {
                    Panel(onClick = onOpenNetwork) {
                        Row(verticalAlignment = Alignment.Top, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            Icon(Icons.Rounded.Warning, null, tint = Palette.Warning)
                            Column {
                                Text("Private DNS may bypass AdShield", style = MaterialTheme.typography.titleMedium)
                                BodyText("Android's Private DNS is set to ${vm.privateDnsHost ?: "a specific provider"}. On some Android versions this makes DNS skip AdShield. Open YouTube protection to see whether lookups are reaching AdShield.")
                            }
                        }
                    }
                }
            }

            item {
                StatTile(
                    "Blocked", totals.blocked, Modifier.fillMaxWidth(),
                    accent = if (protection is ProtectionState.Running) Palette.Teal else Palette.TextPrimary,
                )
            }

            item {
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    QuickAction("Apps", Icons.Rounded.Apps, onOpenApps, Modifier.weight(1f))
                    QuickAction("Blocklists", Icons.Rounded.Block, onOpenLists, Modifier.weight(1f))
                    QuickAction("Network", Icons.Rounded.Wifi, onOpenNetwork, Modifier.weight(1f))
                }
            }

            item { SectionTitle("Blocked by type") }
            item {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        StatTile("Ads", totals.ads, Modifier.weight(1f))
                        StatTile("Trackers", totals.trackers, Modifier.weight(1f))
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        StatTile("Malware", totals.malware, Modifier.weight(1f))
                        StatTile("Phishing", totals.phishing, Modifier.weight(1f))
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        StatTile("Total DNS requests", totals.totalQueries, Modifier.weight(1f))
                        StatTile("Custom rules", totals.custom, Modifier.weight(1f))
                    }
                }
            }

            item { SectionTitle("Status") }
            item {
                Panel {
                    Column {
                        InfoRow(
                            "VPN", if (protection is ProtectionState.Running) "Active (local, DNS only)" else "Inactive",
                            valueColor = if (protection is ProtectionState.Running) Palette.Teal else MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        InfoRow(
                            "Connection",
                            if (network.type == ConnectionType.NONE) "No connection"
                            else network.type.label + if (network.metered) " · metered" else "",
                        )
                        InfoRow(
                            "Filtering engine",
                            when {
                                engine.loading -> "Loading rules…"
                                engine.loaded -> "${formatCount(engine.domainCount.toLong())} domains · ${DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(engine.loadedAtMillis))}"
                                else -> "Loads when protection starts"
                            },
                        )
                        InfoRow(
                            "Service load",
                            if (protection is ProtectionState.Running) "${load.level.label} · ${"%.1f".format(load.cpuPercent)}% CPU · ${load.queriesPerMinute} lookups/min" else "Idle",
                        )
                        Spacer(Modifier.height(4.dp))
                        BodyText("Load is AdShield's own CPU use. Android does not let apps read battery attribution; see Settings › Battery for the system figure.")
                    }
                }
            }
            item {
                Panel(onClick = onOpenBattery) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        IconBadge(Icons.Rounded.Warning, Palette.Warning)
                        Column(Modifier.weight(1f)) {
                            Text("Keep protection reliable", style = MaterialTheme.typography.titleMedium)
                            BodyText("Battery optimization guide")
                        }
                        Pill("Guide", Palette.Teal)
                    }
                }
            }
            item {
                BodyText(
                    "AdShield filters DNS lookups locally. It cannot guarantee that every ad is blocked, and it never inspects or decrypts your traffic.",
                    Modifier.padding(horizontal = 8.dp),
                )
            }
        }
    }
}

@Composable
private fun QuickAction(label: String, icon: androidx.compose.ui.graphics.vector.ImageVector, onClick: () -> Unit, modifier: Modifier = Modifier) {
    Panel(modifier = modifier, onClick = onClick) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            IconBadge(icon)
            Text(label, style = MaterialTheme.typography.labelLarge)
        }
    }
}
