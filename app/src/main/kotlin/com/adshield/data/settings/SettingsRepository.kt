package com.adshield.data.settings

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.adshield.domain.model.BlockMode
import com.adshield.domain.model.UpstreamMode
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "adshield_settings")

data class DnsSettings(
    val blockMode: BlockMode = BlockMode.NULL_IP,
    val upstreamMode: UpstreamMode = UpstreamMode.SYSTEM,
    val customUpstream: String = "",
    val dohUrl: String = DEFAULT_DOH_URL,
    val captureKnownResolvers: Boolean = true,
    val protectStreamingFirstParty: Boolean = true,
    val attributeQueriesToApps: Boolean = true,
) {
    companion object {
        const val DEFAULT_DOH_URL = "https://cloudflare-dns.com/dns-query"
    }
}

@Singleton
class SettingsRepository @Inject constructor(@ApplicationContext private val context: Context) {
    private val store get() = context.dataStore

    private object K {
        val onboardingDone = booleanPreferencesKey("onboarding_done")
        val protectionDesired = booleanPreferencesKey("protection_desired")
        val autoUpdate = booleanPreferencesKey("auto_update_lists")
        val blockMode = stringPreferencesKey("block_mode")
        val upstreamMode = stringPreferencesKey("upstream_mode")
        val customUpstream = stringPreferencesKey("custom_upstream")
        val dohUrl = stringPreferencesKey("doh_url")
        val captureResolvers = booleanPreferencesKey("capture_known_resolvers")
        val protectStreaming = booleanPreferencesKey("protect_streaming_first_party")
        val attribute = booleanPreferencesKey("attribute_queries_to_apps")
    }

    private val data: Flow<Preferences> = store.data.catchIo()

    val onboardingDone: Flow<Boolean> = data.map { it[K.onboardingDone] ?: false }
    val protectionDesired: Flow<Boolean> = data.map { it[K.protectionDesired] ?: false }
    val autoUpdateLists: Flow<Boolean> = data.map { it[K.autoUpdate] ?: true }

    val dns: Flow<DnsSettings> = data.map { p ->
        DnsSettings(
            blockMode = enumOr(p[K.blockMode], BlockMode.NULL_IP),
            upstreamMode = enumOr(p[K.upstreamMode], UpstreamMode.SYSTEM),
            customUpstream = p[K.customUpstream].orEmpty(),
            dohUrl = p[K.dohUrl] ?: DnsSettings.DEFAULT_DOH_URL,
            captureKnownResolvers = p[K.captureResolvers] ?: true,
            protectStreamingFirstParty = p[K.protectStreaming] ?: true,
            attributeQueriesToApps = p[K.attribute] ?: true,
        )
    }

    suspend fun setOnboardingDone(v: Boolean) = store.edit { it[K.onboardingDone] = v }
    suspend fun setProtectionDesired(v: Boolean) = store.edit { it[K.protectionDesired] = v }
    suspend fun protectionDesiredNow(): Boolean = protectionDesired.first()
    suspend fun setAutoUpdateLists(v: Boolean) = store.edit { it[K.autoUpdate] = v }
    suspend fun setBlockMode(v: BlockMode) = store.edit { it[K.blockMode] = v.name }
    suspend fun setUpstreamMode(v: UpstreamMode) = store.edit { it[K.upstreamMode] = v.name }
    suspend fun setCustomUpstream(v: String) = store.edit { it[K.customUpstream] = v.trim() }
    suspend fun setDohUrl(v: String) = store.edit { it[K.dohUrl] = v.trim() }
    suspend fun setCaptureKnownResolvers(v: Boolean) = store.edit { it[K.captureResolvers] = v }
    suspend fun setProtectStreamingFirstParty(v: Boolean) = store.edit { it[K.protectStreaming] = v }
    suspend fun setAttributeQueries(v: Boolean) = store.edit { it[K.attribute] = v }

    private fun Flow<Preferences>.catchIo(): Flow<Preferences> =
        catch { e -> if (e is IOException) emit(emptyPreferences()) else throw e }

    private inline fun <reified E : Enum<E>> enumOr(name: String?, default: E): E =
        enumValues<E>().firstOrNull { it.name == name } ?: default
}
