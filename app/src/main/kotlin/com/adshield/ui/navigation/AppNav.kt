package com.adshield.ui.navigation

import androidx.compose.animation.AnimatedContentTransitionScope
import androidx.compose.animation.EnterTransition
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.BarChart
import androidx.compose.material.icons.rounded.Block
import androidx.compose.material.icons.rounded.MoreHoriz
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import androidx.navigation.NavBackStackEntry
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.adshield.ui.screens.AboutScreen
import com.adshield.ui.screens.AppsScreen
import com.adshield.ui.screens.BatteryGuideScreen
import com.adshield.ui.screens.BlocklistsScreen
import com.adshield.ui.screens.DashboardScreen
import com.adshield.ui.screens.DnsSettingsScreen
import com.adshield.ui.screens.MoreScreen
import com.adshield.ui.screens.NetworkScreen
import com.adshield.ui.screens.OnboardingScreen
import com.adshield.ui.screens.PrivacyScreen
import com.adshield.ui.screens.RulesScreen
import com.adshield.ui.screens.StatsScreen
import com.adshield.ui.screens.YoutubeScreen
import com.adshield.ui.theme.Palette

object Routes {
    const val ONBOARDING = "onboarding"
    const val HOME = "home"
    const val APPS = "apps"
    const val LISTS = "lists"
    const val STATS = "stats"
    const val MORE = "more"
    const val DNS = "dns"
    const val RULES = "rules"
    const val NETWORK = "network"
    const val BATTERY = "battery"
    const val PRIVACY = "privacy"
    const val ABOUT = "about"
    const val YOUTUBE = "youtube"
}

private data class Tab(val route: String, val label: String, val icon: ImageVector)

private val tabs = listOf(
    Tab(Routes.HOME, "Shield", Icons.Rounded.Shield),
    Tab(Routes.APPS, "Apps", Icons.Rounded.Apps),
    Tab(Routes.LISTS, "Lists", Icons.Rounded.Block),
    Tab(Routes.STATS, "Stats", Icons.Rounded.BarChart),
    Tab(Routes.MORE, "More", Icons.Rounded.MoreHoriz),
)

private fun NavHostController.goTab(route: String) = navigate(route) {
    popUpTo(graph.findStartDestination().id) { saveState = true }
    launchSingleTop = true
    restoreState = true
}

@Composable
fun AppNav(startOnboarding: Boolean) {
    val nav = rememberNavController()
    val entry by nav.currentBackStackEntryAsState()
    val route = entry?.destination?.route
    val showBar = tabs.any { it.route == route }

    Scaffold(
        containerColor = androidx.compose.material3.MaterialTheme.colorScheme.background,
        bottomBar = {
            if (showBar) {
                NavigationBar(containerColor = Palette.Surface, tonalElevation = 0.dp) {
                    tabs.forEach { t ->
                        NavigationBarItem(
                            selected = route == t.route, onClick = { nav.goTab(t.route) },
                            icon = { Icon(t.icon, contentDescription = null) }, label = { Text(t.label) },
                            colors = NavigationBarItemDefaults.colors(
                                selectedIconColor = Palette.OnTeal, selectedTextColor = Palette.Teal, indicatorColor = Palette.Teal,
                                unselectedIconColor = Palette.TextSecondary, unselectedTextColor = Palette.TextSecondary,
                            ),
                        )
                    }
                }
            }
        },
    ) { inner ->
        // Each screen has its own Scaffold; the outer one only contributes the bottom bar inset.
        val bottom = inner.calculateBottomPadding()
        NavHost(
            navController = nav,
            startDestination = if (startOnboarding) Routes.ONBOARDING else Routes.HOME,
            modifier = Modifier.padding(bottom = bottom),
            enterTransition = { fadeIn() + slideIn() },
            exitTransition = { fadeOut() },
            popEnterTransition = { fadeIn() },
            popExitTransition = { fadeOut() + slideOutHorizontally { it / 6 } },
        ) {
            composable(Routes.ONBOARDING) {
                OnboardingScreen(onFinished = { nav.navigate(Routes.HOME) { popUpTo(Routes.ONBOARDING) { inclusive = true } } })
            }
            composable(Routes.HOME, enterTransition = { fadeIn() }, exitTransition = { fadeOut() }) {
                DashboardScreen(
                    onOpenApps = { nav.goTab(Routes.APPS) }, onOpenLists = { nav.goTab(Routes.LISTS) },
                    onOpenNetwork = { nav.navigate(Routes.NETWORK) }, onOpenBattery = { nav.navigate(Routes.BATTERY) },
                )
            }
            composable(Routes.APPS, enterTransition = { fadeIn() }, exitTransition = { fadeOut() }) { AppsScreen(onOpenYoutube = { nav.navigate(Routes.YOUTUBE) }) }
            composable(Routes.LISTS, enterTransition = { fadeIn() }, exitTransition = { fadeOut() }) { BlocklistsScreen(onBack = null) }
            composable(Routes.STATS, enterTransition = { fadeIn() }, exitTransition = { fadeOut() }) { StatsScreen() }
            composable(Routes.MORE, enterTransition = { fadeIn() }, exitTransition = { fadeOut() }) {
                MoreScreen(
                    onYoutube = { nav.navigate(Routes.YOUTUBE) }, onDns = { nav.navigate(Routes.DNS) }, onRules = { nav.navigate(Routes.RULES) }, onNetwork = { nav.navigate(Routes.NETWORK) },
                    onBattery = { nav.navigate(Routes.BATTERY) }, onPrivacy = { nav.navigate(Routes.PRIVACY) }, onAbout = { nav.navigate(Routes.ABOUT) },
                )
            }
            composable(Routes.YOUTUBE) { YoutubeScreen(onBack = { nav.popBackStack() }) }
            composable(Routes.DNS) { DnsSettingsScreen(onBack = { nav.popBackStack() }) }
            composable(Routes.RULES) { RulesScreen(onBack = { nav.popBackStack() }) }
            composable(Routes.NETWORK) { NetworkScreen(onBack = { nav.popBackStack() }) }
            composable(Routes.BATTERY) { BatteryGuideScreen(onBack = { nav.popBackStack() }) }
            composable(Routes.PRIVACY) { PrivacyScreen(onBack = { nav.popBackStack() }) }
            composable(Routes.ABOUT) { AboutScreen(onBack = { nav.popBackStack() }) }
        }
    }
}

private fun AnimatedContentTransitionScope<NavBackStackEntry>.slideIn(): EnterTransition = slideInHorizontally { it / 6 }

