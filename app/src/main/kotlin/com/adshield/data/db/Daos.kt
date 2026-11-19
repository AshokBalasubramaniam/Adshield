package com.adshield.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import kotlinx.coroutines.flow.Flow

@Dao
interface BlocklistDao {
    @Query("SELECT * FROM blocklist_source ORDER BY sortOrder, name")
    fun observeAll(): Flow<List<BlocklistEntity>>

    @Query("SELECT * FROM blocklist_source ORDER BY sortOrder, name")
    suspend fun getAll(): List<BlocklistEntity>

    @Query("SELECT * FROM blocklist_source WHERE id = :id")
    suspend fun get(id: String): BlocklistEntity?

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertIfAbsent(entity: BlocklistEntity): Long

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entity: BlocklistEntity)

    @Query("UPDATE blocklist_source SET enabled = :enabled WHERE id = :id")
    suspend fun setEnabled(id: String, enabled: Boolean)

    @Query("UPDATE blocklist_source SET domainCount = :count WHERE id = :id")
    suspend fun setCount(id: String, count: Int)

    @Query("UPDATE blocklist_source SET sha256 = :sha, domainCount = :count, updatedAt = :at, lastError = NULL WHERE id = :id")
    suspend fun markUpdated(id: String, sha: String, count: Int, at: Long)

    @Query("UPDATE blocklist_source SET lastError = :error WHERE id = :id")
    suspend fun setError(id: String, error: String?)

    @Query("UPDATE blocklist_source SET sha256 = NULL, domainCount = 0, updatedAt = 0 WHERE id = :id")
    suspend fun clearDownload(id: String)

    @Query("DELETE FROM blocklist_source WHERE id = :id AND builtIn = 0")
    suspend fun deleteCustom(id: String)
}

@Dao
interface UserRuleDao {
    @Query("SELECT * FROM user_rule ORDER BY domain")
    fun observeAll(): Flow<List<UserRuleEntity>>

    @Query("SELECT * FROM user_rule")
    suspend fun getAll(): List<UserRuleEntity>

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insert(rule: UserRuleEntity): Long

    @Query("DELETE FROM user_rule WHERE id = :id")
    suspend fun delete(id: Long)
}

@Dao
interface AppSettingDao {
    @Query("SELECT packageName FROM app_setting WHERE filteringEnabled = 0")
    fun observeDisabled(): Flow<List<String>>

    @Query("SELECT packageName FROM app_setting WHERE filteringEnabled = 0")
    suspend fun getDisabled(): List<String>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(setting: AppSettingEntity)

    @Query("DELETE FROM app_setting WHERE packageName = :pkg")
    suspend fun clear(pkg: String)
}

@Dao
interface StatsDao {
    @Query("INSERT INTO counter(key, value) VALUES(:key, :delta) ON CONFLICT(key) DO UPDATE SET value = value + :delta")
    suspend fun addCounter(key: String, delta: Long)

    @Query("SELECT * FROM counter")
    fun observeCounters(): Flow<List<CounterEntity>>

    @Query(
        "INSERT INTO app_counter(packageName, total, blocked) VALUES(:pkg, :total, :blocked) " +
            "ON CONFLICT(packageName) DO UPDATE SET total = total + :total, blocked = blocked + :blocked",
    )
    suspend fun addAppCounter(pkg: String, total: Long, blocked: Long)

    @Query("SELECT * FROM app_counter ORDER BY blocked DESC, total DESC LIMIT :limit")
    fun observeTopApps(limit: Int): Flow<List<AppCounterEntity>>

    @Query(
        "INSERT INTO daily_counter(epochDay, total, blocked) VALUES(:day, :total, :blocked) " +
            "ON CONFLICT(epochDay) DO UPDATE SET total = total + :total, blocked = blocked + :blocked",
    )
    suspend fun addDaily(day: Long, total: Long, blocked: Long)

    @Query("SELECT * FROM daily_counter WHERE epochDay >= :sinceDay ORDER BY epochDay")
    fun observeDays(sinceDay: Long): Flow<List<DailyCounterEntity>>

    @Query("DELETE FROM counter")
    suspend fun clearCounters()

    @Query("DELETE FROM app_counter")
    suspend fun clearAppCounters()

    @Query("DELETE FROM daily_counter")
    suspend fun clearDaily()

    @Query("DELETE FROM daily_counter WHERE epochDay < :beforeDay")
    suspend fun pruneDaily(beforeDay: Long)

    @Transaction
    suspend fun resetAll() {
        clearCounters()
        clearAppCounters()
        clearDaily()
    }
}
