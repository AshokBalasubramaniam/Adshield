package com.adshield.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adshield.domain.model.BlockCategory
import com.adshield.domain.model.BlocklistSource
import com.adshield.ui.components.BodyText
import com.adshield.ui.components.Panel
import com.adshield.ui.components.Pill
import com.adshield.ui.components.ScreenScaffold
import com.adshield.ui.components.SectionTitle
import com.adshield.ui.components.SwitchRow
import com.adshield.ui.components.formatCount
import com.adshield.ui.theme.Palette
import java.text.DateFormat
import java.util.Date

@Composable
fun BlocklistsScreen(onBack: (() -> Unit)?, vm: BlocklistsViewModel = hiltViewModel()) {
    val sources by vm.sources.collectAsStateWithLifecycle()
    val engine by vm.engine.collectAsStateWithLifecycle()
    val busy by vm.busy.collectAsStateWithLifecycle()
    val message by vm.message.collectAsStateWithLifecycle()
    val autoUpdate by vm.autoUpdate.collectAsStateWithLifecycle()
    var showAdd by remember { mutableStateOf(false) }
    val allBusy = BlocklistsViewModel.ALL in busy

    ScreenScaffold(title = "Blocklists", onBack = onBack) { padding ->
        LazyColumn(
            Modifier.fillMaxSize(),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = padding.calculateTopPadding() + 4.dp, bottom = padding.calculateBottomPadding() + 24.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            item {
                Panel {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(
                            if (engine.loaded) "${formatCount(engine.domainCount.toLong())} domains loaded" else "Rules load when protection starts",
                            style = MaterialTheme.typography.titleMedium,
                        )
                        BodyText("Lists are downloaded straight from their publishers over HTTPS to this device. AdShield has no server. Each file is size-limited, checked to be a valid domain list, and re-verified by SHA-256 every time it is loaded.")
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                            Button(onClick = { vm.updateAll() }, enabled = !allBusy, colors = ButtonDefaults.buttonColors(containerColor = Palette.Teal, contentColor = Palette.OnTeal)) {
                                if (allBusy) CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp, color = Palette.OnTeal) else Icon(Icons.Rounded.Refresh, null, Modifier.size(18.dp))
                                Spacer(Modifier.width(8.dp)); Text("Update all")
                            }
                            OutlinedButton(onClick = { showAdd = true }) { Icon(Icons.Rounded.Add, null, Modifier.size(18.dp)); Spacer(Modifier.width(8.dp)); Text("Add list") }
                        }
                        SwitchRow("Refresh lists automatically", autoUpdate, { vm.setAutoUpdate(it) }, subtitle = "Checked while protection is on. Only on unmetered networks and when the battery is not low.")
                    }
                }
            }
            message?.let { msg -> item { Panel { Row(verticalAlignment = Alignment.CenterVertically) { Text(msg, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium); TextButton(onClick = vm::clearMessage) { Text("OK") } } } } }
            item { SectionTitle("Lists") }
            items(sources, key = { it.id }) { src -> SourceCard(src, src.id in busy, vm) }
            item { BodyText("Blocking whole content-delivery networks is avoided. A built-in safety net also keeps video CDNs, DRM licence servers and connectivity checks from being blocked by any public list.") }
        }
    }

    if (showAdd) AddListDialog(onDismiss = { showAdd = false }, onAdd = { n, u, c, done -> vm.addCustom(n, u, c, done) })
    LaunchedEffect(message) { if (message != null) kotlinx.coroutines.delay(6000).also { vm.clearMessage() } }
}

@Composable
private fun SourceCard(src: BlocklistSource, busy: Boolean, vm: BlocklistsViewModel) {
    Panel {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(src.name, style = MaterialTheme.typography.titleMedium)
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.padding(top = 4.dp)) {
                        Pill(src.category.label, Palette.Teal)
                        if (!src.builtIn) Pill("Custom", Palette.TextSecondary)
                    }
                }
                Switch(
                    checked = src.enabled, onCheckedChange = { vm.setEnabled(src.id, it) },
                    colors = SwitchDefaults.colors(checkedThumbColor = Palette.OnTeal, checkedTrackColor = Palette.Teal, uncheckedThumbColor = Palette.TextSecondary, uncheckedTrackColor = Palette.SurfaceHigh, uncheckedBorderColor = Palette.Outline),
                )
            }
            BodyText(src.description)
            val status = when {
                src.url == null -> "Bundled · ${formatCount(src.domainCount.toLong())} domains"
                src.updatedAt == 0L -> "Not downloaded yet" + if (src.sizeNote.isNotEmpty()) " (${src.sizeNote})" else ""
                else -> "${formatCount(src.domainCount.toLong())} domains · updated ${DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(src.updatedAt))}"
            }
            Text(status, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurface)
            Text("License: ${src.license}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            src.sha256?.let { Text("SHA-256 ${it.take(16)}…", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
            src.lastError?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = Palette.Danger) }
            if (src.url != null) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    TextButton(onClick = { vm.update(src.id) }, enabled = !busy) {
                        if (busy) CircularProgressIndicator(Modifier.size(14.dp), strokeWidth = 2.dp, color = Palette.Teal) else Icon(Icons.Rounded.Refresh, null, Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp)); Text("Update")
                    }
                    if (!src.builtIn) TextButton(onClick = { vm.remove(src.id) }) { Icon(Icons.Rounded.Delete, null, Modifier.size(16.dp)); Spacer(Modifier.width(6.dp)); Text("Remove") }
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AddListDialog(onDismiss: () -> Unit, onAdd: (String, String, BlockCategory, (String?) -> Unit) -> Unit) {
    var name by remember { mutableStateOf("") }
    var url by remember { mutableStateOf("") }
    var category by remember { mutableStateOf(BlockCategory.ADS) }
    var error by remember { mutableStateOf<String?>(null) }
    var working by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = { if (!working) onDismiss() },
        title = { Text("Add custom blocklist") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                BodyText("Hosts files, plain domain lists and simple ||domain^ rules are supported. HTTPS only.")
                OutlinedTextField(name, { name = it }, label = { Text("Name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(url, { url = it; error = null }, label = { Text("https:// URL") }, singleLine = true, modifier = Modifier.fillMaxWidth(), isError = error != null, supportingText = { error?.let { Text(it) } }, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf(BlockCategory.ADS, BlockCategory.TRACKER, BlockCategory.MALWARE, BlockCategory.PHISHING).forEach { c ->
                        FilterChip(selected = category == c, onClick = { category = c }, label = { Text(c.label) })
                    }
                }
            }
        },
        confirmButton = {
            TextButton(enabled = !working, onClick = {
                working = true
                onAdd(name, url, category) { err -> working = false; if (err == null) onDismiss() else error = err }
            }) { if (working) CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp) else Text("Add & download") }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !working) { Text("Cancel") } },
    )
}
