package com.adshield.data.repo

import android.content.Context
import android.provider.Settings

/** Reads Android's Private DNS mode (a world-readable global setting; no permission required). */
object PrivateDnsMode {
    enum class Mode { OFF, AUTOMATIC, STRICT, UNKNOWN }

    /** Host name configured for strict Private DNS (e.g. "dns.adguard.com"), or null. */
    fun hostname(context: Context): String? =
        Settings.Global.getString(context.contentResolver, "private_dns_specifier")?.takeIf { it.isNotBlank() }

    fun read(context: Context): Mode = when (Settings.Global.getString(context.contentResolver, "private_dns_mode")) {
        "off" -> Mode.OFF
        "opportunistic" -> Mode.AUTOMATIC
        "hostname" -> Mode.STRICT
        else -> Mode.UNKNOWN
    }
}
