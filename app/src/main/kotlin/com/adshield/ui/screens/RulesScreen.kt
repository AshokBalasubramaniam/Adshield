package com.adshield.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
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
import com.adshield.ui.components.BodyText
import com.adshield.ui.components.Panel
import com.adshield.ui.components.Pill
import com.adshield.ui.components.ScreenScaffold
import com.adshield.ui.theme.Palette
import kotlinx.coroutines.launch

/** Allowlist (never block) and custom block rules in one place. A rule covers the domain and all its subdomains. */
@Composable
fun RulesScreen(onBack: (() -> Unit)?, vm: RulesViewModel = hiltViewModel()) {
    val rules by vm.rules.collectAsStateWithLifecycle()
    var tab by remember { mutableIntStateOf(0) }
    val isAllow = tab == 0
    var input by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    fun submit() {
        scope.launch {
            when (vm.add(input, isAllow)) {
                AddRuleResult.ADDED -> { input = ""; error = null }
                AddRuleResult.INVALID -> error = "Not a valid domain (example: ads.example.com)"
                AddRuleResult.DUPLICATE -> error = "That rule already exists"
            }
        }
    }

    ScreenScaffold(title = "Allow & block rules", onBack = onBack) { padding ->
        Column(Modifier.fillMaxSize().padding(top = padding.calculateTopPadding())) {
            TabRow(selectedTabIndex = tab, containerColor = MaterialTheme.colorScheme.background, contentColor = Palette.Teal) {
                Tab(selected = isAllow, onClick = { tab = 0; error = null }, text = { Text("Allowlist") })
                Tab(selected = !isAllow, onClick = { tab = 1; error = null }, text = { Text("Custom blocks") })
            }
            LazyColumn(
                Modifier.fillMaxSize(),
                contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 12.dp, bottom = padding.calculateBottomPadding() + 24.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                item {
                    Panel {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            BodyText(
                                if (isAllow) "Allowed domains (and their subdomains) are never blocked. Use this if a site or app breaks. Per-app allow rules are managed from the Apps screen."
                                else "Custom blocks add your own domains. They also work for hosts the built-in safety net normally protects, so use them with care.",
                            )
                            OutlinedTextField(
                                input, { input = it; error = null }, Modifier.fillMaxWidth(), singleLine = true,
                                label = { Text(if (isAllow) "Domain to allow" else "Domain to block") },
                                isError = error != null, supportingText = { error?.let { Text(it) } },
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Done),
                                keyboardActions = KeyboardActions(onDone = { submit() }),
                            )
                            Button(onClick = ::submit, enabled = input.isNotBlank(), colors = ButtonDefaults.buttonColors(containerColor = Palette.Teal, contentColor = Palette.OnTeal)) {
                                Text(if (isAllow) "Add to allowlist" else "Block domain")
                            }
                        }
                    }
                }
                val shown = rules.filter { it.isAllow == isAllow }
                if (shown.isEmpty()) item { BodyText("No rules yet.", Modifier.padding(8.dp)) }
                items(shown, key = { it.id }) { r ->
                    Panel {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(r.domain, style = MaterialTheme.typography.titleMedium)
                                Pill(if (r.packageName.isEmpty()) "All apps" else vm.labelOf(r.packageName), Palette.TextSecondary, Modifier.padding(top = 4.dp))
                            }
                            IconButton(onClick = { vm.remove(r.id) }) { Icon(Icons.Rounded.Close, "Remove ${r.domain}") }
                        }
                    }
                }
            }
        }
    }
}
