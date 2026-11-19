package com.adshield.data.db

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(tableName = "blocklist_source")
data class BlocklistEntity(
    @PrimaryKey val id: String,
    val name: String,
    val description: String,
    val url: String?,
    val category: String,
    val enabled: Boolean,
    val builtIn: Boolean,
    val license: String,
    val domainCount: Int = 0,
    val sha256: String? = null,
    val updatedAt: Long = 0,
    val lastError: String? = null,
    val sizeNote: String = "",
    val sortOrder: Int = 0,
)

@Entity(tableName = "user_rule", indices = [Index(value = ["domain", "isAllow", "packageName"], unique = true)])
data class UserRuleEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val domain: String,
    val isAllow: Boolean,
    /** Empty string = global rule. */
    val packageName: String = "",
)

/** Only apps whose filtering was explicitly switched off are ever stored with enabled=false. */
@Entity(tableName = "app_setting")
data class AppSettingEntity(@PrimaryKey val packageName: String, val filteringEnabled: Boolean)

@Entity(tableName = "counter")
data class CounterEntity(@PrimaryKey val key: String, val value: Long)

@Entity(tableName = "app_counter")
data class AppCounterEntity(@PrimaryKey val packageName: String, val total: Long, val blocked: Long)

@Entity(tableName = "daily_counter")
data class DailyCounterEntity(@PrimaryKey val epochDay: Long, val total: Long, val blocked: Long)
