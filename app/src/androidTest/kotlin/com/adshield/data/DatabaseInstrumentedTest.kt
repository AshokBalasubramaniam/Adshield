package com.adshield.data

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.adshield.data.db.AdShieldDatabase
import com.adshield.data.db.AppSettingEntity
import com.adshield.data.db.BlocklistEntity
import com.adshield.data.db.UserRuleEntity
import com.adshield.data.rules.BuiltInLists
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Room integration tests. Run on a device/emulator: ./gradlew :app:connectedDebugAndroidTest */
@RunWith(AndroidJUnit4::class)
class DatabaseInstrumentedTest {
    private lateinit var db: AdShieldDatabase

    @Before fun open() {
        db = Room.inMemoryDatabaseBuilder(ApplicationProvider.getApplicationContext<Context>(), AdShieldDatabase::class.java).allowMainThreadQueries().build()
    }
    @After fun close() = db.close()

    @Test fun seedingNeverOverwritesUserChoices() = runBlocking {
        val dao = db.blocklistDao()
        BuiltInLists.all.forEach { dao.insertIfAbsent(it) }
        dao.setEnabled("adaway", false)
        BuiltInLists.all.forEach { dao.insertIfAbsent(it) } // app restart
        assertEquals(false, dao.get("adaway")!!.enabled)
        assertEquals(BuiltInLists.all.size, dao.getAll().size)
    }

    @Test fun customListsCanBeDeletedBuiltInsCannot() = runBlocking {
        val dao = db.blocklistDao()
        BuiltInLists.all.forEach { dao.insertIfAbsent(it) }
        dao.upsert(BlocklistEntity("custom-1", "mine", "", "https://x.example/l", "ADS", true, false, "?"))
        dao.deleteCustom("custom-1"); dao.deleteCustom("adaway")
        assertTrue(dao.get("custom-1") == null); assertTrue(dao.get("adaway") != null)
    }

    @Test fun userRulesAreUniquePerDomainTypeAndApp() = runBlocking {
        val dao = db.userRuleDao()
        assertTrue(dao.insert(UserRuleEntity(domain = "a.com", isAllow = true)) > 0)
        assertEquals(-1L, dao.insert(UserRuleEntity(domain = "a.com", isAllow = true)))
        assertTrue(dao.insert(UserRuleEntity(domain = "a.com", isAllow = true, packageName = "com.x")) > 0)
        assertTrue(dao.insert(UserRuleEntity(domain = "a.com", isAllow = false)) > 0)
        assertEquals(3, dao.getAll().size)
    }

    @Test fun onlyDisabledAppsAreStored() = runBlocking {
        val dao = db.appSettingDao()
        dao.upsert(AppSettingEntity("com.a", false)); dao.upsert(AppSettingEntity("com.b", false))
        dao.clear("com.a")
        assertEquals(listOf("com.b"), dao.observeDisabled().first())
    }

    @Test fun counterUpsertsAccumulateAndResetClearsEverything() = runBlocking {
        val dao = db.statsDao()
        dao.addCounter("total", 5); dao.addCounter("total", 7); dao.addCounter("ads", 2)
        dao.addAppCounter("com.a", 3, 1); dao.addAppCounter("com.a", 2, 2); dao.addDaily(20000, 10, 4); dao.addDaily(20000, 1, 1)
        assertEquals(12L, dao.observeCounters().first().first { it.key == "total" }.value)
        val app = dao.observeTopApps(5).first().single(); assertEquals(5L, app.total); assertEquals(3L, app.blocked)
        val day = dao.observeDays(0).first().single(); assertEquals(11L, day.total); assertEquals(5L, day.blocked)
        dao.resetAll()
        assertTrue(dao.observeCounters().first().isEmpty() && dao.observeTopApps(5).first().isEmpty() && dao.observeDays(0).first().isEmpty())
    }
}
