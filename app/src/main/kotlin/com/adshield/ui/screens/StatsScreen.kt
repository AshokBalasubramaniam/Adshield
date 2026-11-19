package com.adshield.ui.screens

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adshield.domain.model.DayStat
import com.adshield.ui.components.BodyText
import com.adshield.ui.components.InfoRow
import com.adshield.ui.components.Panel
import com.adshield.ui.components.Pill
import com.adshield.ui.components.ScreenScaffold
import com.adshield.ui.components.SectionTitle
import com.adshield.ui.components.formatCount
import com.adshield.ui.theme.Palette
import java.text.DateFormat
import java.time.LocalDate
import java.time.format.TextStyle
import java.util.Date
import java.util.Locale

@Composable
fun StatsScreen(vm: StatsViewModel = hiltViewModel()) {
    val totals by vm.totals.collectAsStateWithLifecycle()
    val days by vm.days.collectAsStateWithLifecycle()
    val apps by vm.topApps.collectAsStateWithLifecycle()
    val recent by vm.recent.collectAsStateWithLifecycle()
    var confirmReset by remember { mutableStateOf(false) }

    ScreenScaffold(title = "Statistics") { padding ->
        LazyColumn(
            Modifier.fillMaxSize(),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = padding.calculateTopPadding() + 4.dp, bottom = padding.calculateBottomPadding() + 24.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            item {
                Panel {
                    Column {
                        InfoRow("Total DNS requests", formatCount(totals.totalQueries))
                        InfoRow("Blocked", formatCount(totals.blocked), valueColor = Palette.Teal)
                        InfoRow("Allowed", formatCount(totals.allowed))
                        InfoRow("Answered from cache", formatCount(totals.cacheHits))
                        InfoRow("Failed upstream", formatCount(totals.failures), valueColor = if (totals.failures > 0) Palette.Warning else MaterialTheme.colorScheme.onSurface)
                    }
                }
            }

            item { SectionTitle("Blocked by type") }
            item {
                Panel {
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        val max = maxOf(1L, totals.ads, totals.trackers, totals.malware, totals.phishing, totals.custom)
                        Bar("Ads", totals.ads, max); Bar("Trackers", totals.trackers, max); Bar("Malware", totals.malware, max)
                        Bar("Phishing", totals.phishing, max); Bar("Custom rules", totals.custom, max)
                    }
                }
            }

            item { SectionTitle("Last 7 days") }
            item { Panel { DayChart(days) } }

            item { SectionTitle("Most active apps") }
            item {
                Panel {
                    Column {
                        if (apps.isEmpty()) BodyText("No data yet.")
                        apps.forEach { a ->
                            InfoRow(
                                if (a.packageName.isEmpty()) "System resolver (unattributed)" else a.label,
                                "${formatCount(a.blocked)} / ${formatCount(a.total)}",
                            )
                        }
                        BodyText("Blocked / total lookups. Android usually resolves names in the system resolver, so most lookups are unattributed.")
                    }
                }
            }

            item { SectionTitle("Recently blocked (memory only)") }
            item {
                Panel {
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        if (recent.isEmpty()) BodyText("Nothing blocked in this session yet.")
                        recent.take(15).forEach { r ->
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Column(Modifier.weight(1f)) {
                                    Text(r.domain, style = MaterialTheme.typography.bodyMedium, maxLines = 1)
                                    Text(DateFormat.getTimeInstance(DateFormat.MEDIUM).format(Date(r.atMillis)), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                                Pill(r.category.label, Palette.TextSecondary)
                            }
                        }
                        BodyText("The last 50 blocked names are kept in memory only so you can see what is happening. They are never written to disk, and are cleared when protection stops or statistics are reset.")
                    }
                }
            }

            item {
                OutlinedButton(onClick = { confirmReset = true }, modifier = Modifier.fillMaxWidth()) { Text("Reset statistics") }
            }
            item { BodyText("All statistics are counted on this device and never leave it.") }
        }
    }

    if (confirmReset) {
        AlertDialog(
            onDismissRequest = { confirmReset = false },
            title = { Text("Reset statistics?") },
            text = { Text("All counters, per-app figures and the recent list will be erased. Your rules and settings are kept.") },
            confirmButton = { TextButton(onClick = { vm.reset(); confirmReset = false }) { Text("Reset") } },
            dismissButton = { TextButton(onClick = { confirmReset = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun Bar(label: String, value: Long, max: Long) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row { Text(label, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant); Text(formatCount(value), style = MaterialTheme.typography.bodyMedium) }
        Box(Modifier.fillMaxWidth().height(8.dp).clip(RoundedCornerShape(4.dp)).background(Palette.SurfaceHigh)) {
            Box(Modifier.fillMaxHeight().fillMaxWidth((value.toFloat() / max).coerceIn(0f, 1f)).clip(RoundedCornerShape(4.dp)).background(Palette.Teal))
        }
    }
}

@Composable
private fun DayChart(days: List<DayStat>) {
    val today = LocalDate.now()
    val byDay = days.associateBy { it.epochDay }
    val series = (6 downTo 0).map { off -> val d = today.minusDays(off.toLong()); d to byDay[d.toEpochDay()] }
    val max = maxOf(1L, series.maxOf { it.second?.total ?: 0L })
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Canvas(Modifier.fillMaxWidth().height(110.dp)) {
            val slot = size.width / series.size
            val barW = slot * 0.5f
            series.forEachIndexed { i, (_, st) ->
                val x = i * slot + (slot - barW) / 2
                val totalH = size.height * ((st?.total ?: 0L).toFloat() / max)
                val blockedH = size.height * ((st?.blocked ?: 0L).toFloat() / max)
                drawRoundRect(Palette.SurfaceHigh, Offset(x, size.height - totalH.coerceAtLeast(2f)), Size(barW, totalH.coerceAtLeast(2f)), CornerRadius(6f))
                if (blockedH > 0f) drawRoundRect(Palette.Teal, Offset(x, size.height - blockedH), Size(barW, blockedH), CornerRadius(6f))
            }
        }
        Row(Modifier.fillMaxWidth()) {
            series.forEach { (d, _) -> Text(d.dayOfWeek.getDisplayName(TextStyle.SHORT, Locale.getDefault()), Modifier.weight(1f), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, textAlign = androidx.compose.ui.text.style.TextAlign.Center) }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Legend(Palette.Teal, "Blocked"); Legend(Palette.SurfaceHigh, "All lookups")
        }
    }
}

@Composable
private fun Legend(color: Color, text: String) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        Box(Modifier.size(10.dp).clip(RoundedCornerShape(3.dp)).background(color))
        Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
