package com.adshield.vpn

import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.core.content.ContextCompat
import com.adshield.data.repo.ProtectionStateHolder
import com.adshield.domain.model.ProtectionState
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/** UI-facing entry point for turning protection on and off. */
@Singleton
class ProtectionController @Inject constructor(
    @ApplicationContext private val context: Context,
    private val stateHolder: ProtectionStateHolder,
) {
    /** Non-null when the system VPN consent dialog must be shown first. */
    fun consentIntent(): Intent? = VpnService.prepare(context)

    /** Call only after consent. The state becomes Running only once the service has really started the tunnel. */
    fun start() {
        stateHolder.set(ProtectionState.Starting("Starting"))
        try {
            ContextCompat.startForegroundService(
                context, Intent(context, AdShieldVpnService::class.java).setAction(VpnConfig.ACTION_START),
            )
        } catch (e: IllegalStateException) {
            stateHolder.set(ProtectionState.Error("Android would not start the protection service: ${e.message}"))
        } catch (e: SecurityException) {
            stateHolder.set(ProtectionState.Error("Permission denied starting the protection service: ${e.message}"))
        }
    }

    fun stop() {
        if (stateHolder.state.value is ProtectionState.Stopped) return
        context.startService(Intent(context, AdShieldVpnService::class.java).setAction(VpnConfig.ACTION_STOP))
    }
}
