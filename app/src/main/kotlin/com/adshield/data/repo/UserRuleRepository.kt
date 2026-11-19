package com.adshield.data.repo

import com.adshield.data.db.UserRuleDao
import com.adshield.data.db.UserRuleEntity
import com.adshield.domain.model.UserRule
import com.adshield.engine.DomainNormalizer
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

enum class AddRuleResult { ADDED, INVALID, DUPLICATE }

@Singleton
class UserRuleRepository @Inject constructor(private val dao: UserRuleDao) {
    val rules: Flow<List<UserRule>> = dao.observeAll().map { l -> l.map { UserRule(it.id, it.domain, it.isAllow, it.packageName) } }

    /** Accepts pasted URLs too ("https://ads.example.com/path" → "ads.example.com"). */
    suspend fun add(input: String, isAllow: Boolean, packageName: String = ""): AddRuleResult {
        val domain = DomainNormalizer.normalizeRuleDomain(extractHost(input)) ?: return AddRuleResult.INVALID
        return if (dao.insert(UserRuleEntity(domain = domain, isAllow = isAllow, packageName = packageName)) == -1L) {
            AddRuleResult.DUPLICATE
        } else {
            AddRuleResult.ADDED
        }
    }

    suspend fun remove(id: Long) = dao.delete(id)

    companion object {
        fun extractHost(input: String): String {
            var s = input.trim()
            s = s.substringAfter("://", s).substringBefore('/').substringBefore('?').substringBefore('#')
            s = s.substringAfterLast('@').substringBefore(':')
            return s.removePrefix("*.")
        }
    }
}
