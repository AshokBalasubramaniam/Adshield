package com.adshield.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.RadioButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adshield.domain.model.BlockMode
import com.adshield.domain.model.UpstreamMode
import com.adshield.ui.components.BodyText
import com.adshield.ui.components.Panel
import com.adshield.ui.components.ScreenScaffold
import com.adshield.ui.components.SectionTitle
import com.adshield.ui.components.SwitchRow
import com.adshield.ui.theme.Palette
import kotlinx.coroutines.launch

@Composable
fun DnsSettingsScreen(onBack: (() -> Unit)?, vm: DnsSettingsViewModel = hiltViewModel()) {
    val s by vm.dns.collectAsStateWithLifecycle()
    val running by vm.running.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var custom by remember(s.customUpstream) { mutableStateOf(s.customUpstream) }
    var customError by remember { mutableStateOf<String?>(null) }
    var doh by remember(s.dohUrl) { mutableStateOf(s.dohUrl) }
    var dohError by remember { mutableStateOf<String?>(null) }

    ScreenScaffold(title = "DNS filtering", onBack = onBack) { padding ->
        LazyColumn(
            Modifier.fillMaxSize(),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = padding.calculateTopPadding() + 4.dp, bottom = padding.calculateBottomPadding() + 24.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            if (running) item { BodyText("Changes apply immediately while protection is on.") }

            item { SectionTitle("When a domain is blocked") }
            item {
                Panel {
                    Column {
                        BlockMode.entries.forEach { m -> RadioRow(m.label, m.description, s.blockMode == m) { vm.setBlockMode(m) } }
                    }
                }
            }

            item { SectionTitle("Upstream DNS (for allowed lookups)") }
            item {
                Panel {
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        RadioRow(UpstreamMode.SYSTEM.label, "Uses the DNS servers of your current Wi-Fi or mobile network. Queries are sent unencrypted, as they would be without AdShield.", s.upstreamMode == UpstreamMode.SYSTEM) { vm.setUpstreamMode(UpstreamMode.SYSTEM) }
                        RadioRow(UpstreamMode.CUSTOM.label, "A resolver you choose, by IP address. Unencrypted.", s.upstreamMode == UpstreamMode.CUSTOM) { vm.setUpstreamMode(UpstreamMode.CUSTOM) }
                        if (s.upstreamMode == UpstreamMode.CUSTOM) {
                            OutlinedTextField(
                                custom, { custom = it; customError = null }, Modifier.fillMaxWidth(), singleLine = true,
                                label = { Text("IP address(es), e.g. 9.9.9.9, 149.112.112.112") }, isError = customError != null, supportingText = { customError?.let { Text(it) } },
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                            )
                            Button(onClick = { scope.launch { customError = vm.saveCustomUpstream(custom) } }, colors = ButtonDefaults.buttonColors(containerColor = Palette.Teal, contentColor = Palette.OnTeal)) { Text("Save") }
                        }
                        RadioRow(UpstreamMode.DOH.label, "Encrypts AdShield's upstream lookups with HTTPS (RFC 8484). The provider sees your lookups; pick one you trust.", s.upstreamMode == UpstreamMode.DOH) { vm.setUpstreamMode(UpstreamMode.DOH) }
                        if (s.upstreamMode == UpstreamMode.DOH) {
                            OutlinedTextField(
                                doh, { doh = it; dohError = null }, Modifier.fillMaxWidth(), singleLine = true,
                                label = { Text("DoH endpoint (https://…)") }, isError = dohError != null, supportingText = { dohError?.let { Text(it) } },
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                            )
                            Button(onClick = { scope.launch { dohError = vm.saveDohUrl(doh) } }, colors = ButtonDefaults.buttonColors(containerColor = Palette.Teal, contentColor = Palette.OnTeal)) { Text("Save") }
                            BodyText("Certificates are validated by Android with default settings. The DoH server's own host name is looked up via your network's DNS.")
                        }
                    }
                }
            }

            item { SectionTitle("Leak protection") }
            item {
                Panel {
                    SwitchRow(
                        "Also capture well-known public resolvers", s.captureKnownResolvers, { vm.setCapture(it) },
                        subtitle = "Apps that hard-code DNS like 8.8.8.8 or 1.1.1.1 are filtered too. TCP/DoT to these addresses is refused so apps fall back to filtered DNS.",
                    )
                }
            }

            item { SectionTitle("Streaming apps") }
            item {
                Panel {
                    SwitchRow(
                        "Protect streaming first-party domains", s.protectStreamingFirstParty, { vm.setProtectStreaming(it) },
                        subtitle = "On (default): YouTube and Hotstar first-party hosts are never blocked by public lists, because sign-in, playback and DRM share them. Off (“aggressive”): lists may block ad/analytics hosts there, and playback may break.",
                    )
                }
            }

            item { SectionTitle("Attribution") }
            item {
                Panel {
                    SwitchRow(
                        "Attribute lookups to apps (best effort)", s.attributeQueriesToApps, { vm.setAttribute(it) },
                        subtitle = "Needed for per-app statistics and per-app allow rules. Depends on the Android version; if attribution never succeeds AdShield slows down its attempts (and keeps probing occasionally).",
                    )
                }
            }

            item { SectionTitle("What DNS filtering cannot do") }
            item {
                Panel {
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        BodyText("•  AdShield never intercepts or decrypts HTTPS. It sees only DNS lookups, not page content.", color = MaterialTheme.colorScheme.onSurface)
                        BodyText("•  Apps that carry their own encrypted DNS (DoH/DoT to a name AdShield cannot see) are not filtered.", color = MaterialTheme.colorScheme.onSurface)
                        BodyText("•  If Android's Private DNS is set to a specific provider, lookups may bypass AdShield depending on the Android version. Automatic or Off is the safe choice.", color = MaterialTheme.colorScheme.onSurface)
                        BodyText("•  Ads served from the same domain as content cannot be separated from it.", color = MaterialTheme.colorScheme.onSurface)
                    }
                }
            }
        }
    }
}

@Composable
private fun RadioRow(title: String, subtitle: String, selected: Boolean, onSelect: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(role = Role.RadioButton, onClick = onSelect).padding(vertical = 6.dp),
        verticalAlignment = Alignment.Top,
    ) {
        RadioButton(selected, onClick = null, colors = RadioButtonDefaults.colors(selectedColor = Palette.Teal), modifier = Modifier.padding(top = 2.dp, end = 12.dp))
        Column {
            Text(title, style = MaterialTheme.typography.titleMedium)
            BodyText(subtitle)
        }
    }
}

