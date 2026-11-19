package com.adshield.data.db

import androidx.room.Database
import androidx.room.RoomDatabase

@Database(
    entities = [
        BlocklistEntity::class, UserRuleEntity::class, AppSettingEntity::class,
        CounterEntity::class, AppCounterEntity::class, DailyCounterEntity::class,
    ],
    version = 1,
    exportSchema = true,
)
abstract class AdShieldDatabase : RoomDatabase() {
    abstract fun blocklistDao(): BlocklistDao
    abstract fun userRuleDao(): UserRuleDao
    abstract fun appSettingDao(): AppSettingDao
    abstract fun statsDao(): StatsDao
}
