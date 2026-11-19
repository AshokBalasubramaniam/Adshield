package com.adshield.data.repo

import com.adshield.domain.model.ProtectionState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Single source of truth for what the UI shows. [ProtectionState.Running] is only ever set by the VPN
 * service after the tunnel interface exists and packet processing is active. Because this object lives
 * in the app process, a killed process can never leave a stale "Running" value behind.
 */
@Singleton
class ProtectionStateHolder @Inject constructor() {
    private val _state = MutableStateFlow<ProtectionState>(ProtectionState.Stopped)
    val state: StateFlow<ProtectionState> = _state.asStateFlow()

    /** Epoch-millis (elapsed realtime) at which the current Running period began, 0 when not running. */
    @Volatile
    var runningSinceElapsed: Long = 0
        private set

    fun set(newState: ProtectionState, elapsedNow: Long = android.os.SystemClock.elapsedRealtime()) {
        runningSinceElapsed = if (newState is ProtectionState.Running) {
            if (_state.value is ProtectionState.Running) runningSinceElapsed else elapsedNow
        } else {
            0
        }
        _state.value = newState
    }
}
