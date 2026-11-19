# AdShield security & privacy assessment

Scope: the application as built from this repository. This is a self-assessment by the authoring team, not an independent penetration test. Items marked **Open** need action or on-device confirmation.

## 1. Assets and trust boundaries

| Asset | Where it lives | Who can reach it |
|---|---|---|
| DNS queries from apps (domain names) | In memory inside the app process, only while protection is on | Only AdShield's process; the VPN interface is owned by the app |
| Counters, rules, per-app switches | Room DB in app-private storage | Only AdShield (backup disabled) |
| Downloaded filter lists | `filesDir/blocklists/*.txt` (app-private) | Only AdShield |
| Upstream DNS answers | In-memory cache (≤2048 entries, ≤300 s TTL) | Only AdShield |

Trust boundaries: (a) apps → tunnel (untrusted packets), (b) device → list publishers over the internet (untrusted content), (c) device → upstream resolver (untrusted answers), (d) user → settings input (untrusted strings).

## 2. Threats and mitigations

| # | Threat | Mitigation | Evidence |
|---|---|---|---|
| T1 | Malformed / hostile packets crash or exploit the parser | Every read is bounds-checked; failures return `null`, never throw. IPv4 fragments, IPv6 extension headers and bad lengths are dropped. DNS names reject compression pointers in questions, over-long labels/names and non-printable bytes; response parsing caps pointer hops. | `IpPacketTest`, `DnsMessageTest` (20 000+ random and mutated inputs each, truncation at every length) |
| T2 | Resource exhaustion by a flood of queries | Max 64 concurrent queries (extra are dropped, clients retry); bounded output queue (256); bounded caches (decision 4096, DNS 2048); upstream timeout; `Semaphore.tryAcquire` never blocks the reader. | `TunnelLoop` |
| T3 | Tampered or poisoned blocklist (could block essential sites or exfiltrate nothing, but cause DoS) | HTTPS-only incl. redirects, 30 MB cap, "must look like a domain list" check, shrink guard (<50 % of previous), atomic replace, SHA-256 stored and re-verified on every load, discard-on-mismatch. Essential domains (video CDN, DRM, connectivity, sign-in) can never be blocked by a list. | `ListDownloaderTest`, `AdFilteringEngineTest` |
| T4 | TLS downgrade / MITM on list or DoH fetches | Default platform validation only; no custom `TrustManager`/`HostnameVerifier`; network security config: no cleartext, system CAs only. | `PrivacyPolicyTest.neverWeakensTlsValidation`, `cleartextIsOffAndBackupIsOff` |
| T5 | Upstream DNS loops back into the tunnel / leaks via another path | Own app excluded from the VPN; upstream sockets and DoH connections are bound to the physical `Network`; with no network the query fails (SERVFAIL) rather than falling back to another route. | `UpstreamFactory`, `UpstreamLoopbackTest` |
| T6 | DNS leaks around the filter | Routes for the virtual resolver and well-known public resolvers (plain DNS); TCP/853/443 to those addresses is RST'd so clients fall back to filtered DNS. | `VpnConfig`, `TunnelLoop`, Network status screen |
| T7 | Spoofed upstream response | Transaction-ID must match the query; connected UDP socket (only the chosen server's source is accepted). Source-port randomisation is provided by the OS. No DNSSEC validation (**not claimed**). | `UdpTcpDnsUpstream` |
| T8 | Developer-side data collection | No servers, SDKs, analytics, crash reporters or ad IDs; build fails if any appear. | `PrivacyPolicyTest.noAnalyticsOrAdvertisingDependencies`, permission test |
| T9 | Over-broad permissions / package visibility | Exactly 5 permissions; apps listed through a launcher-intent `<queries>` element, not `QUERY_ALL_PACKAGES`. | `PrivacyPolicyTest.requestsExactlyTheMinimumPermissions` |
| T10 | Traffic accidentally routed wholesale through the tunnel | Only `/32` and `/128` routes are added; a test fails the build if a default route or `allowBypass` appears. | `PrivacyPolicyTest.vpnServiceAddsOnlyDnsRoutesNeverADefaultRoute` |
| T11 | Another app abusing the VPN service | Service is exported only because the system must bind it, and is protected by the signature permission `BIND_VPN_SERVICE`. Start/stop intents are handled inside the app; the notification action uses an immutable `PendingIntent`. | Manifest |
| T12 | Sensitive data in logs | Domain names are never written to disk or to release-build logs. **Debug builds only** mirror YouTube-related decisions to logcat (tag `AdShieldDiag`, guarded by `BuildConfig.DEBUG`) for development; release builds contain no such statement (checked in the release dex). The in-app YouTube log is memory-only, bounded (1,500), opt-in, cleared when protection stops, and exported only by explicit user action through the system file picker. | Code review, dex check |
| T14 | Memory/CPU exhaustion or state confusion in the new TCP DNS responder | At most 64 sessions, 15 s idle expiry, 64 KiB per message, zero-length message → RST, only passive opens, no retransmission state. Out-of-order/duplicate data is re-ACKed, never re-delivered. 20 000 random segment sequences never throw. | `TcpDnsSessionsTest` |
| T15 | CNAME parsing abuse (pointer loops, oversized/invalid names, truncation) | Hop cap 16, 253-char cap, syntax validation, at most 64 answers examined; malformed names skipped. Fuzzed with 30 000 mutated and 30 000 random messages, truncated at every length. | `CnameParserTest` |
| T16 | Diagnostics leaking browsing history | Only YouTube-related names (or lookups attributed to the YouTube app) are recorded; recording is off by default; counters hold no names; nothing persisted; no network code references the log. | `YoutubeDiagnosticsTest`, `PrivacyPolicyTest` |
| T13 | Malicious user-supplied URL / domain / IP | List URLs: https only, host required, no embedded credentials. Custom upstream accepts numeric IP literals only (no resolution). DoH URL validated. Rules validated by `DomainNormalizer`. | `ListDownloaderTest`, `UpstreamLoopbackTest`, `DomainNormalizerTest` |

## 3. Privacy review

* **Processed locally:** DNS query names and types; the app that asked when Android reveals it.
* **Persisted:** aggregate counters (total/allowed/blocked per type, per app, per day for 30 days), rules, settings. **No domain names are persisted.**
* **In memory only:** the last 50 blocked names (for the Stats screen); cleared on stop and reset.
* **Leaves the device:** (1) list downloads to publishers (GitHub, GitLab) when updating; (2) allowed DNS lookups to the configured upstream, exactly as without AdShield; nothing else. Both are disclosed in the Privacy screen and onboarding.
* **Not collected:** identifiers, location, contacts, storage, installed-app inventory (never leaves the device; used only to render the app list).

## 4. Android platform considerations

* `FOREGROUND_SERVICE_SPECIAL_USE` is used (with the required `PROPERTY_SPECIAL_USE_FGS_SUBTYPE`). **Open:** Google Play requires a declaration form for this type; sideloaded builds are unaffected. `systemExempted` was deliberately rejected after Lint reported it needs exact-alarm permissions that a VPN app should not request.
* Android 14+ foreground-service rules, Android 13+ notification permission: handled (the service runs even if the notification permission is denied).
* Per-app attribution via `getConnectionOwnerUid` is best-effort (system resolver usually owns the socket) — documented in UI and README.

## 5. Findings log

| ID | Severity | Finding | Status |
|---|---|---|---|
| F1 | Medium (would crash on Android 10–12) | `InputStream.readNBytes` (API 33) used in the DoH reader. Found by Android Lint. | **Fixed** — bounded manual read, unit-tested (`BoundedReadTest`). |
| F2 | Medium (potential `SecurityException` on Android 14+) | `systemExempted` foreground-service type has preconditions a VPN app may not meet. Found by Android Lint. | **Fixed** — switched to `specialUse`. |
| F3 | Low | Default list URL (URLhaus hostfile) returned HTTP 410 at integration time. | **Fixed** — switched to the maintained malware-filter republication; downloader reports failures per list rather than failing silently. |
| F9 | Medium (privacy requirement) | WorkManager injected `WAKE_LOCK` and `RECEIVE_BOOT_COMPLETED` into the *merged* manifest; the source-manifest test could not see it. Found by dumping the release APK's permissions. | **Fixed** — WorkManager removed; list refresh now runs inside the protection service (unmetered + battery-not-low only). Build task `verifyReleasePermissions` now fails the build on any unapproved merged permission (verified to fail when `WAKE_LOCK` is injected). |
| F10 | Medium (filtering gap) | CNAME-cloaked ad/tracker hosts were not filtered; cached answers were never re-checked against updated rules. | **Fixed** and tested. |
| F11 | Medium (reliability) | All TCP DNS was refused (RST), so truncated UDP answers could not be completed. | **Fixed** (minimal, bounded TCP responder). Device behaviour unverified. |
| F12 | Medium (feature silently dead) | App attribution gave up permanently after 200 unattributed lookups. | **Fixed** (keeps probing 1 in 20). |
| F13 | Medium (diagnosability) | Block decisions did not identify the list/rule responsible. | **Fixed** (per-list sets, rule and list id on every decision). |
| F14 | Low (documentation accuracy) | Two statements were contradicted by the first device run: that Android usually hides the app owning DNS sockets, and that strict Private DNS bypasses the VPN's DNS. | **Corrected** in UI copy and docs; evidence in `YOUTUBE_ROOT_CAUSE_ANALYSIS.md` §7. |
| F15 | Low | `InstallSourceInfo` (API 30) used with minSdk 29 would crash on Android 10. Found by Android Lint. | **Fixed** (SDK guard + deprecated fallback). |
| F4 | Info | Aggregated "unified hosts" lists mix licenses; | **Mitigated** — only single-license lists are shipped by default; licenses are shown per list. |
| F5 | Open | No DNSSEC validation; plain upstream DNS is unencrypted unless DoH is selected. | Documented; DoH option provided. |
| F6 | Fixed (device-unverified) | Virtual DNS server did not support DNS-over-TCP. | Minimal TCP responder added and tested at packet level; confirm on device. |
| F7 | Open | Behaviour on real devices (OEM battery managers, always-on VPN, Private DNS strict, multi-user/work profiles) not yet validated. | See `TEST_PLAN.md`. |
| F8 | Open | Phishing list aggregates feeds with non-commercial terms. | Fine for non-commercial use; review before commercial distribution. |

## 6. Static analysis and tooling

Android Lint (debug + release), detekt (project config in `config/detekt/detekt.yml`), Kotlin compiler warnings, R8 minification for release, OSV.dev dependency scan (`tools/osv_scan.py`, report in `docs/DEPENDENCY_REPORT.md`).
