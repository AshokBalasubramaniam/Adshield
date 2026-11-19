package com.adshield.data.repo

import android.content.Context
import android.provider.Settings

/** Reads Android's Private DNS mode (a world-readable global setting; no permission required). */
object PrivateDnsMode {
    enum class Mode { OFF, AUTOMATIC, STRICT, UNKNOWN }

    fun read(context: Context): Mode = when (Settings.Global.getString(context.contentResolver, "private_dns_mode")) {
        "off" -> Mode.OFF
        "opportunistic" -> Mode.AUTOMATIC
        "hostname" -> Mode.STRICT
        else -> Mode.UNKNOWN
    }
}
