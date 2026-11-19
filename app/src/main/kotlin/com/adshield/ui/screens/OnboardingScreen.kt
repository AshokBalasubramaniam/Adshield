package com.adshield.ui.screens

import android.Manifest
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adshield.ui.components.BodyText
import com.adshield.ui.components.IconBadge
import com.adshield.ui.theme.Palette
import kotlinx.coroutines.launch

private data class Page(val icon: ImageVector, val tint: androidx.compose.ui.graphics.Color, val title: String, val body: List<String>)

private val pages = listOf(
    Page(Icons.Rounded.Shield, Palette.Teal, "Block ads and trackers on your device", listOf(
        "AdShield creates a local VPN that handles only your device's DNS lookups, the step where an app asks “where is ads.example.com?”.",
        "Known advertising, tracking, malware and phishing domains get no answer, so apps cannot reach them.",
    )),
    Page(Icons.Rounded.Warning, Palette.Warning, "What it can and cannot do", listOf(
        "DNS filtering works best when ads come from separate ad-network domains.",
        "Ads delivered from the same servers as the content, such as many in-stream video ads in YouTube or JioHotstar, cannot be told apart from the video. AdShield does not promise to remove them, and never bypasses subscriptions or DRM.",
        "Apps with their own encrypted DNS are not filtered. AdShield never decrypts HTTPS.",
    )),
    Page(Icons.Rounded.VerifiedUser, Palette.Teal, "Private by design", listOf(
        "Everything runs on this device. There is no AdShield server, no account, no analytics and no ads.",
        "AdShield reads DNS lookups in memory to filter them. Only counters are stored, never your browsing history. Details are in the privacy policy.",
    )),
    Page(Icons.Rounded.Dns, Palette.Teal, "Get your filter lists", listOf(
        "AdShield works offline with a small built-in list. For much wider coverage it can download maintained public lists straight from their publishers (GitHub, GitLab) over HTTPS. Those hosts will see your IP address, like any download.",
    )),
)

@Composable
fun OnboardingScreen(onFinished: () -> Unit, vm: OnboardingViewModel = hiltViewModel()) {
    val pager = rememberPagerState(pageCount = { pages.size })
    val scope = rememberCoroutineScope()
    val download by vm.download.collectAsStateWithLifecycle()
    val last = pager.currentPage == pages.lastIndex
    val notificationLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }

    Column(Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background).statusBarsPadding().navigationBarsPadding().padding(24.dp)) {
        Box(Modifier.weight(1f)) {
            HorizontalPager(pager, Modifier.fillMaxSize()) { i ->
                val p = pages[i]
                Column(Modifier.fillMaxSize(), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
                    IconBadge(p.icon, p.tint, size = 96.dp)
                    Spacer(Modifier.height(28.dp))
                    Text(p.title, style = MaterialTheme.typography.headlineMedium, textAlign = TextAlign.Center)
                    Spacer(Modifier.height(16.dp))
                    p.body.forEach { BodyText(it, Modifier.padding(vertical = 4.dp).fillMaxWidth(), color = MaterialTheme.colorScheme.onSurfaceVariant) }
                    if (i == pages.lastIndex) {
                        Spacer(Modifier.height(20.dp))
                        when (val d = download) {
                            is ListDownloadUi.Idle -> OutlinedButton(onClick = { vm.downloadLists() }) { Text("Download lists now") }
                            is ListDownloadUi.Running -> Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                                CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp, color = Palette.Teal); Text("Downloading…")
                            }
                            is ListDownloadUi.Done -> BodyText(
                                if (d.failed == 0) "Lists ready." else "${d.ok} list(s) ready, ${d.failed} failed. You can retry later in Blocklists.",
                                color = if (d.failed == 0) Palette.Teal else Palette.Warning,
                            )
                        }
                    }
                }
            }
        }
        Row(Modifier.fillMaxWidth().padding(vertical = 12.dp), horizontalArrangement = Arrangement.Center) {
            repeat(pages.size) { i ->
                Box(Modifier.padding(4.dp).size(if (i == pager.currentPage) 10.dp else 8.dp).clip(CircleShape).background(if (i == pager.currentPage) Palette.Teal else Palette.Outline))
            }
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = { scope.launch { if (pager.currentPage > 0) pager.animateScrollToPage(pager.currentPage - 1) } }, enabled = pager.currentPage > 0) { Text("Back") }
            Button(
                onClick = {
                    if (last) {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) notificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                        vm.finish(onFinished)
                    } else scope.launch { pager.animateScrollToPage(pager.currentPage + 1) }
                },
                colors = ButtonDefaults.buttonColors(containerColor = Palette.Teal, contentColor = Palette.OnTeal),
            ) { Text(if (last) "Get started" else "Next") }
        }
    }
}
