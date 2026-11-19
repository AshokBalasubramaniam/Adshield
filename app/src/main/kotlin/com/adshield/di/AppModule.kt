package com.adshield.di

import android.content.Context
import androidx.room.Room
import com.adshield.data.db.AdShieldDatabase
import com.adshield.dns.DnsCache
import com.adshield.engine.AdFilteringEngine
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {
    @Provides @Singleton
    fun database(@ApplicationContext context: Context): AdShieldDatabase =
        Room.databaseBuilder(context, AdShieldDatabase::class.java, "adshield.db").build()

    @Provides fun blocklistDao(db: AdShieldDatabase) = db.blocklistDao()
    @Provides fun userRuleDao(db: AdShieldDatabase) = db.userRuleDao()
    @Provides fun appSettingDao(db: AdShieldDatabase) = db.appSettingDao()
    @Provides fun statsDao(db: AdShieldDatabase) = db.statsDao()

    @Provides @Singleton
    fun engine(): AdFilteringEngine = AdFilteringEngine()

    @Provides @Singleton
    fun dnsCache(): DnsCache = DnsCache()

    @Provides @Singleton
    fun appScope(): CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
}
