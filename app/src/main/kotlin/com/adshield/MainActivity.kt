package com.adshield

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adshield.ui.navigation.AppNav
import com.adshield.ui.screens.MainViewModel
import com.adshield.ui.theme.AdShieldTheme
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        val splash = installSplashScreen()
        super.onCreate(savedInstanceState)
        // Keep the system splash (shield icon on charcoal) until we know whether to show onboarding.
        splash.setKeepOnScreenCondition { viewModel.onboardingDone.value == null }
        enableEdgeToEdge()
        setContent {
            AdShieldTheme {
                val done by viewModel.onboardingDone.collectAsStateWithLifecycle()
                done?.let { AppNav(startOnboarding = !it) }
            }
        }
    }
}
