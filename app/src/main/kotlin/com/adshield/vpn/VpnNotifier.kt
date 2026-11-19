package com.adshield.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import com.adshield.MainActivity
import com.adshield.R

class VpnNotifier(private val context: Context) {
    private val manager = context.getSystemService(NotificationManager::class.java)

    init {
        manager.createNotificationChannel(
            NotificationChannel(
                VpnConfig.NOTIFICATION_CHANNEL,
                context.getString(R.string.notification_channel_name),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = context.getString(R.string.notification_channel_desc)
                setShowBadge(false)
            },
        )
    }

    fun build(text: String): Notification {
        val open = PendingIntent.getActivity(
            context, 0, Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stop = PendingIntent.getService(
            context, 1, Intent(context, AdShieldVpnService::class.java).setAction(VpnConfig.ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(context, VpnConfig.NOTIFICATION_CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_shield)
            .setContentTitle(context.getString(R.string.app_name))
            .setContentText(text)
            .setContentIntent(open)
            .addAction(0, context.getString(R.string.action_turn_off), stop)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    fun update(text: String) = runCatching { manager.notify(VpnConfig.NOTIFICATION_ID, build(text)) }
}
