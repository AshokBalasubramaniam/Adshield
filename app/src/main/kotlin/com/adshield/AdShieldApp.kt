package com.adshield

import android.app.Application
import com.adshield.data.rules.RuleManager
import dagger.hilt.android.HiltAndroidApp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltAndroidApp
class AdShieldApp : Application() {
    @Inject lateinit var ruleManager: RuleManager
    @Inject lateinit var appScope: CoroutineScope

    override fun onCreate() {
        super.onCreate()
        appScope.launch {
            runCatching { ruleManager.ensureSeeded() }
        }
    }
}
