package com.adshield.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.ExpandLess
import androidx.compose.material.icons.rounded.ExpandMore
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adshield.data.repo.AddRuleResult
import com.adshield.domain.model.CompatEntry
import com.adshield.domain.model.CompatLevel
import com.adshield.domain.model.AppCompatibility
import com.adshield.ui.components.AppIcon
import com.adshield.ui.components.BodyText
import com.adshield.ui.components.Panel
import com.adshield.ui.components.Pill
import com.adshield.ui.components.ScreenScaffold
import com.adshield.ui.components.SectionTitle
import com.adshield.ui.components.SwitchRow
import com.adshield.ui.components.formatCount
import com.adshield.ui.theme.Palette
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppsScreen(vm: AppsViewModel = hiltViewModel()) {
    val rows by vm.rows.collectAsStateWithLifecycle()
    val loading by vm.loading.collectAsStateWithLifecycle()
    val query by vm.query.collectAsStateWithLifecycle()
    val selected by vm.selected.collectAsStateWithLifecycle()
    val disabledCount by vm.disabledCount.collectAsStateWithLifecycle()

    ScreenScaffold(title = "Apps") { padding ->
        LazyColumn(
            Modifier.fillMaxSize(),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = padding.calculateTopPadding() + 4.dp, bottom = padding.calculateBottomPadding() + 24.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            item { SectionTitle("Compatibility") }
            items(AppCompatibility.featured) { entry -> CompatCard(entry, installed = vm.installed(entry.packages).isNotEmpty()) }
            item { CompatCard(AppCompatibility.others, installed = null) }

            item { SectionTitle("Filter per app") }
            item {
                BodyText("Apps you switch off bypass AdShield completely: their DNS is not filtered and not counted. Changing this briefly restarts the local VPN.")
            }
            if (disabledCount > 0) {
                item {
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Text("$disabledCount app(s) excluded", style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                        TextButton(onClick = { vm.enableAll() }) { Text("Enable all") }
                    }
                }
            }
            item {
                OutlinedTextField(
                    value = query, onValueChange = { vm.query.value = it }, modifier = Modifier.fillMaxWidth(), singleLine = true,
                    placeholder = { Text("Search apps") },
                    leadingIcon = { Icon(Icons.Rounded.Search, null) },
                    trailingIcon = { if (query.isNotEmpty()) IconButton(onClick = { vm.query.value = "" }) { Icon(Icons.Rounded.Close, "Clear search") } },
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                )
            }
            if (loading) {
                item { Box(Modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) { CircularProgressIndicator(color = Palette.Teal) } }
            }
            items(rows, key = { it.app.packageName }) { row ->
                Panel(onClick = { vm.select(row.app.packageName) }) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        AppIcon(row.app.packageName)
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(row.app.label, style = MaterialTheme.typography.titleMedium, maxLines = 1)
                            Text(
                                if (row.total > 0) "${formatCount(row.blocked)} blocked of ${formatCount(row.total)}" else row.app.packageName,
                                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1,
                            )
                        }
                        androidx.compose.material3.Switch(
                            checked = row.app.filteringEnabled, onCheckedChange = { vm.setEnabled(row.app.packageName, it) },
                            colors = androidx.compose.material3.SwitchDefaults.colors(
                                checkedThumbColor = Palette.OnTeal, checkedTrackColor = Palette.Teal,
                                uncheckedThumbColor = Palette.TextSecondary, uncheckedTrackColor = Palette.SurfaceHigh, uncheckedBorderColor = Palette.Outline,
                            ),
                        )
                    }
                }
            }
        }
    }

    val pkg = selected
    if (pkg != null) {
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ModalBottomSheet(onDismissRequest = { vm.select(null) }, sheetState = sheetState, containerColor = MaterialTheme.colorScheme.surface) {
            AppDetail(pkg, vm)
        }
    }
}

@Composable
private fun CompatCard(entry: CompatEntry, installed: Boolean?) {
    var open by remember { mutableStateOf(false) }
    Panel(onClick = { open = !open }) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(entry.name, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                if (installed != null) { Pill(if (installed) "Installed" else "Not installed", Palette.TextSecondary); Spacer(Modifier.width(8.dp)) }
                Pill(entry.level.label, if (entry.level == CompatLevel.LIMITED) Palette.Warning else Palette.Teal)
                Icon(if (open) Icons.Rounded.ExpandLess else Icons.Rounded.ExpandMore, contentDescription = if (open) "Collapse" else "Expand")
            }
            BodyText(entry.summary)
            AnimatedVisibility(open) {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    entry.details.forEach { BodyText("•  $it", color = MaterialTheme.colorScheme.onSurface) }
                }
            }
        }
    }
}

@Composable
private fun AppDetail(pkg: String, vm: AppsViewModel) {
    val rows by vm.rows.collectAsStateWithLifecycle()
    val rules by vm.appRules.collectAsStateWithLifecycle()
    val row = rows.firstOrNull { it.app.packageName == pkg }
    var domain by remember(pkg) { mutableStateOf("") }
    var message by remember(pkg) { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    Column(Modifier.fillMaxWidth().navigationBarsPadding().padding(horizontal = 20.dp).padding(bottom = 20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            AppIcon(pkg, 48.dp)
            Spacer(Modifier.width(12.dp))
            Column {
                Text(row?.app?.label ?: vm.labelOf(pkg), style = MaterialTheme.typography.titleLarge)
                Text(pkg, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        SwitchRow("Filter this app", row?.app?.filteringEnabled ?: true, { vm.setEnabled(pkg, it) }, subtitle = "Off = this app's DNS bypasses AdShield")
        BodyText(
            if ((row?.total ?: 0) > 0) "Statistics: ${formatCount(row!!.blocked)} blocked of ${formatCount(row.total)} lookups attributed to this app."
            else "No lookups attributed to this app yet. Android usually resolves names in the system resolver, so attribution is best-effort.",
        )
        SectionTitle("Allowed domains for this app")
        BodyText("An allowed domain is never blocked for this app. Works only when Android lets AdShield attribute the lookup to the app.")
        rules.forEach { r ->
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(r.domain, Modifier.weight(1f), style = MaterialTheme.typography.bodyLarge)
                IconButton(onClick = { vm.removeRule(r.id) }) { Icon(Icons.Rounded.Close, "Remove ${r.domain}") }
            }
        }
        OutlinedTextField(
            value = domain, onValueChange = { domain = it; message = null }, modifier = Modifier.fillMaxWidth(), singleLine = true,
            label = { Text("Domain, e.g. ads.example.com") }, isError = message != null, supportingText = { message?.let { Text(it) } },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Done),
        )
        TextButton(onClick = {
            scope.launch {
                when (vm.addAllow(domain)) {
                    AddRuleResult.ADDED -> { domain = ""; message = null }
                    AddRuleResult.INVALID -> message = "Not a valid domain"
                    AddRuleResult.DUPLICATE -> message = "Already allowed for this app"
                }
            }
        }) { Text("Allow domain") }
        Spacer(Modifier.height(8.dp))
    }
}
