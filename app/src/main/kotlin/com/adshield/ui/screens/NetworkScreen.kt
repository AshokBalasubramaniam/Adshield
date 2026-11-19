package com.adshield.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adshield.data.repo.PrivateDnsMode
import com.adshield.domain.model.ConnectionType
import com.adshield.domain.model.ProtectionState
import com.adshield.domain.model.UpstreamMode
import com.adshield.ui.components.BodyText
import com.adshield.ui.components.InfoRow
import com.adshield.ui.components.Panel
import com.adshield.ui.components.Pill
import com.adshield.ui.components.ScreenScaffold
import com.adshield.ui.components.SectionTitle
import com.adshield.ui.theme.Palette

private data class Check(val title: String, val detail: String, val ok: Boolean?)

@Composable
fun NetworkScreen(onBack: (() -> Unit)?, vm: NetworkViewModel = hiltViewModel()) {
    val net by vm.network.collectAsStateWithLifecycle()
    val protection by vm.protection.collectAsStateWithLifecycle()
    val dns by vm.dns.collectAsStateWithLifecycle()
    val privateDns = vm.privateDns
    val running = protection is ProtectionState.Running

    val checks = listOf(
        Check("Local VPN", if (running) "Active. Only DNS is routed through it; other traffic bypasses the tunnel." else "Not running, so DNS is not being filtered.", running),
        Check(
            "Upstream path",
            when (dns.upstreamMode) {
                UpstreamMode.SYSTEM -> "Allowed lookups go to your network's DNS servers, bound to the physical network (unencrypted)."
                UpstreamMode.CUSTOM -> "Allowed lookups go to ${dns.customUpstream.ifBlank { "your custom server" }}, bound to the physical network (unencrypted)."
                UpstreamMode.DOH -> "Allowed lookups are encrypted with DNS-over-HTTPS to ${runCatching { java.net.URL(dns.dohUrl).host }.getOrDefault("your DoH server")}."
            },
            true,
        ),
        Check(
            "Hard-coded resolvers",
            if (dns.captureKnownResolvers) "Plain DNS to well-known resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9 …) is captured and filtered." else "Not captured: apps using their own plain DNS server bypass AdShield.",
            dns.captureKnownResolvers,
        ),
        Check(
            "Android Private DNS",
            when (privateDns) {
                PrivateDnsMode.Mode.OFF -> "Off. Compatible."
                PrivateDnsMode.Mode.AUTOMATIC -> "Automatic. Compatible: Android falls back to AdShield's plain DNS."
                PrivateDnsMode.Mode.STRICT -> "Set to a specific provider. Depending on the Android version, DNS may bypass AdShield or fail. On the Android 17 test phone lookups still reached AdShield; check the YouTube protection counters on yours. Automatic or Off is the safe choice."
                PrivateDnsMode.Mode.UNKNOWN -> "Could not be read."
            },
            when (privateDns) { PrivateDnsMode.Mode.STRICT -> false; PrivateDnsMode.Mode.UNKNOWN -> null; else -> true },
        ),
        Check("Apps with their own encrypted DNS", "Cannot be inspected or filtered. AdShield never decrypts HTTPS. Some browsers have a “secure DNS” setting you can turn off.", null),
    )

    ScreenScaffold(title = "Network status", onBack = onBack) { padding ->
        LazyColumn(
            Modifier.fillMaxSize(),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = padding.calculateTopPadding() + 4.dp, bottom = padding.calculateBottomPadding() + 24.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            item { SectionTitle("Current network") }
            item {
                Panel {
                    Column {
                        InfoRow("Connection", net.type.label)
                        if (net.type != ConnectionType.NONE) {
                            InfoRow("Internet validated", if (net.validated) "Yes" else "Not confirmed")
                            InfoRow("Metered", if (net.metered) "Yes" else "No")
                            InfoRow("IPv6", if (net.ipv6Available) "Available" else "Not available")
                            InfoRow("Network DNS servers", net.dnsServers.joinToString("\n").ifEmpty { "None reported" })
                        }
                        BodyText("AdShield follows the active physical network and switches automatically between Wi-Fi and mobile data, clearing cached answers when the network changes.")
                    }
                }
            }
            item { SectionTitle("DNS leak check") }
            checks.forEach { c ->
                item {
                    Panel {
                        Row(verticalAlignment = Alignment.Top, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            Column(Modifier.weight(1f)) {
                                Text(c.title, style = MaterialTheme.typography.titleMedium)
                                BodyText(c.detail)
                            }
                            val (label, color) = when (c.ok) { true -> "OK" to Palette.Teal; false -> "Attention" to Palette.Warning; null -> "Limit" to Palette.TextSecondary }
                            Pill(label, color as Color)
                        }
                    }
                }
            }
            item { Column(Modifier.padding(8.dp)) { BodyText("These checks describe configuration. They do not test your connection, and no test traffic is sent to any server.") } }
        }
    }
}
