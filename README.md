# AdShield

A private, on-device DNS ad, tracker, malware and phishing blocker for Android (API 29+), built with Kotlin, Jetpack Compose, Material 3, Hilt, Room, DataStore and a local `VpnService`.

**No AdShield server exists.** DNS lookups are filtered on the phone; nothing about your browsing is sent to the developer or anyone else by AdShield.

> **Honest scope.** DNS filtering blocks ads that come from separate ad-network domains. It **cannot** remove ads that are served from the same infrastructure as the content, which includes many in-stream video ads in YouTube and JioHotstar. AdShield shows an honest *Limited · not verified* status for those apps and never claims guaranteed ad removal. It does not bypass subscriptions, DRM, sign-in or payments, does not modify other apps and never decrypts HTTPS.

## How it works

```
 app → system resolver ──► tun (10.111.222.2 / fd53:4144:5348::2)      ← only DNS addresses are routed here
                                   │  IPv4/IPv6 + UDP/53 parsed with strict bounds checks
                                   ▼
                        DnsQueryProcessor
                          ├─ normalise name
                          ├─ AdFilteringEngine ── allow rules ▸ block rules ▸ essential-domain safety net ▸ malware ▸ phishing ▸ tracker ▸ ad lists
                          ├─ blocked  → local answer (0.0.0.0 / :: or NXDOMAIN)           [never leaves the device]
                          ├─ DnsCache (TTL-aware LRU)
                          └─ upstream (UDP→TCP on truncation, or DoH), sockets bound to the *physical* network
```

* The tunnel carries **only DNS**: routes cover the virtual DNS addresses and, optionally, well-known public resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9 …) so apps that hard-code them are filtered too. Video, browsing and downloads never enter the tunnel, which is what keeps battery and CPU use low. TCP SYNs reaching the tunnel get an immediate RST, so DoT/TCP-DNS clients fall back to filtered UDP quickly.
* AdShield's own traffic (list downloads, upstream DNS) is excluded from its tunnel and bound to the physical network, so it cannot loop and cannot leak through a different path.
* **ON is only shown when the tunnel exists and packet processing is live.** The state lives in one in-process holder written by the service; a killed process cannot leave a stale "ON".
* Recovery: if the interface dies, the service retries with exponential back-off (up to 6 attempts), then reports an error instead of pretending. Android's own restart (`START_STICKY`) and Always-on VPN are honoured; after a system restart AdShield only resumes if you had it switched on and VPN consent is still valid.
* Network changes (Wi-Fi ⇄ mobile data) are tracked with a `NetworkCallback`; upstream sockets are rebuilt for the new network and cached answers are flushed.

## Features (as requested)

| Area | Implementation |
|---|---|
| One-tap ON/OFF | Dashboard power button → notification permission → system VPN consent → foreground service → rules load → tunnel → state `Running`. OFF cancels the loop, closes the interface, removes the foreground notification, flushes stats. |
| Filtering engine | `engine/`: suffix-aware `HashSet` lookup (O(labels)), LRU decision cache, atomic immutable rule snapshot swap, precedence rules documented in `AdFilteringEngine`. |
| Lists | AdAway (CC BY 3.0), 1Hosts Lite (MPL-2.0), URLhaus via malware-filter (CC0), phishing-filter (mixed upstream feeds, non-commercial terms), plus bundled offline seed lists (Apache-2.0). Add your own `https://` list. |
| List integrity | HTTPS only (every redirect hop), 30 MB cap, timeouts, must parse as a domain list, shrink guard, atomic replace, SHA-256 stored and **re-verified on every load** (tampered/corrupt files are discarded). |
| Per-app | Apps you switch off use `addDisallowedApplication` and bypass the VPN. Per-app allow rules and per-app stats work when Android lets AdShield attribute the lookup (see limitations). |
| DNS | A/AAAA/HTTPS/other types, compression-safe parsing, timeouts, TTL cache, optional DNS-over-HTTPS upstream (RFC 8484), custom resolver by IP. |
| Dashboard / stats | Real counters only (blocked ads/trackers/malware/phishing/custom, total, cache hits, failures), 7-day chart, per-app table, in-memory "recent blocked" list. Reset button. |
| Screens | Splash (system splash API), onboarding, dashboard, apps, DNS settings, blocklists, allow/block rules, statistics, network status + leak check, battery guide, privacy policy, about. |
| Icon | Adaptive + monochrome vector icon (white shield, teal blocked-ad card, charcoal), no text. `docs/icon-512.png` is a rendered preview. |

## Essential-domain safety net

Public lists sometimes contain hosts that break playback. A built-in set can never be blocked **by a list**: video CDNs (`googlevideo.com`, `ytimg.com`, `ggpht.com`, `gstatic.com`), `widevine.com` DRM, connectivity checks, push and sign-in. YouTube and Hotstar **first-party** domains are protected by default too, because authentication, playback APIs and DRM licensing share them with ad/analytics hosts. Consequence: first-party ad hosts there are not blocked. Advanced users can switch on *Aggressive streaming mode* (DNS settings) at the risk of broken playback. A user's own block rule always wins.

## Build

Requirements: JDK 17, Android SDK 36 (`ANDROID_HOME` set), network access for Gradle.

```bash
./gradlew assembleDebug                 # app/build/outputs/apk/debug/app-debug.apk
./gradlew assembleRelease               # minified + resource-shrunk; unsigned unless keystore.properties exists
./gradlew testDebugUnitTest             # JVM unit + pipeline integration tests (no device needed)
./gradlew lintDebug lintRelease detekt  # Android Lint + static analysis
./gradlew connectedDebugAndroidTest     # Room integration tests (needs device/emulator)
```

Release signing: create `keystore.properties` (git-ignored) with `storeFile`, `storePassword`, `keyAlias`, `keyPassword`.

Dependency vulnerability scan (queries OSV.dev with exact resolved versions; only public coordinates are sent):

```bash
./gradlew :app:dependencies --configuration releaseRuntimeClasspath > build/deps-release.txt
python3 tools/osv_scan.py build/deps-release.txt --out docs/DEPENDENCY_REPORT.md
```

## Project layout

```
app/src/main/kotlin/com/adshield/
  engine/    DomainNormalizer, DomainSet, RuleParser, AdFilteringEngine, EssentialDomains, IpLiteral   (pure Kotlin)
  dns/       DnsMessage (parser/builder), DnsCache, DnsUpstream (UDP/TCP, DoH), DnsQueryProcessor     (pure Kotlin)
  vpn/       AdShieldVpnService, TunnelLoop, packet/IpPackets, UpstreamFactory, AppUidResolver, controller, notifier
  data/      Room (db), DataStore (settings), rules (downloader, manager, built-in lists), repositories, NetworkMonitor
  domain/    models, honest app-compatibility statements
  ui/        Compose theme, components, navigation, screens + view models
docs/        SECURITY_ASSESSMENT.md, DEPENDENCY_REPORT.md, TEST_PLAN.md, icon-512.png
tools/       osv_scan.py
```

`engine/`, `dns/` and `vpn/packet/` contain no Android types, so the whole decision path is unit-tested on the JVM, including fuzzing with random and mutated packets.

## Verification status (read this)

| Check | Result |
|---|---|
| Unit + pipeline-integration tests (`testDebugUnitTest`) | ✅ **151 passed, 0 failed** (breakdown in `docs/TEST_PLAN.md`) |
| Android Lint, debug and release | ✅ **0 errors** (remaining warnings are "newer dependency version available" notices) |
| detekt (project config) | ✅ 0 issues |
| Release build (R8 minified, resources shrunk) | ✅ builds; `app-release-unsigned.apk` ≈ 3.0 MB |
| Shipped permissions (merged manifest, checked by the build task `verifyReleasePermissions` and `aapt2`) | ✅ exactly INTERNET, ACCESS_NETWORK_STATE, FOREGROUND_SERVICE, FOREGROUND_SERVICE_SPECIAL_USE, POST_NOTIFICATIONS |
| Dependency scan (OSV.dev, 143 resolved artifacts) | ✅ 0 known advisories on 2026-11-19 (`docs/DEPENDENCY_REPORT.md`) |
| Instrumented Room tests | ⚠️ compile, but **not executed** (no device/emulator available) |
| **Run on a real device / emulator** | ❌ **Not done in the authoring environment** (no hardware virtualisation). The VPN service, consent flow, notification, per-app routing, recovery and battery behaviour are implemented against documented Android APIs and covered by pure-Kotlin tests for everything that does not need the OS, but they **must be validated on devices** with `docs/TEST_PLAN.md` before release. |
| Verified ad removal in YouTube / JioHotstar | ❌ Not verified, and not claimed. |

Bugs found by this tooling and fixed during development are listed in `docs/SECURITY_ASSESSMENT.md` §5 (an API-33-only call that would crash on Android 10–12, a foreground-service type with unmet preconditions, and WorkManager silently adding `WAKE_LOCK` and `RECEIVE_BOOT_COMPLETED`, which led to removing WorkManager).

## YouTube protection (investigation and profile)

`docs/YOUTUBE_ROOT_CAUSE_ANALYSIS.md` explains why YouTube ads still appear: in-stream ads come from the same hosts as the video and the player API, so a DNS filter **cannot** separate them. This work therefore did not add blocklist entries (guessing hosts would be unsafe) and instead added: CNAME-aware filtering, TCP DNS, per-list attribution of every decision, a **YouTube protection screen** (More → YouTube protection) with real session counters, a bounded in-memory diagnostic log (opt-in, export only on request), DNS-bypass signals, a Safe/Aggressive YouTube profile, and an honest playback-compatibility indicator. It never claims an ad was blocked because a lookup was.

Check `docs/PERFORMANCE_COMPARISON.md` for the measured cost of these changes (rule lookups got faster and allocate about half as much as before).

## Known limitations

* **Same-origin ads** (in-stream video ads, first-party feed ads) cannot be blocked by DNS.
* **Encrypted DNS inside apps** (DoH/DoT to a hostname) is invisible to AdShield and is not filtered. AdShield never decrypts HTTPS. Some browsers have a "secure DNS" toggle.
* **Android Private DNS set to a specific provider** may bypass the VPN's DNS or make lookups fail depending on the Android version. On the Android 17 test phone with Private DNS = `dns.adguard.com` AdShield still received the apps' lookups, but this is one device. Use *Automatic* or *Off* to be safe. The app detects the mode and the YouTube screen's counters show whether lookups arrive.
* **Per-app attribution is best-effort and Android-version dependent.** On the Android 17 test phone (Galaxy S24) lookups were attributed to the YouTube app. Older versions may report the system resolver instead; AdShield then records "system resolver" and slows its attempts (it keeps probing 1 in 20). Per-app *switches* are reliable on every version (they use VPN routing).
* **DNS-over-TCP is served by a minimal responder** (handshake, in-order data, chunking, FIN; bounded to 64 sessions). It is not a general TCP stack and has no retransmission timer; it has been tested at packet level only, **not yet on a device**.
* **Plain upstream DNS is unencrypted** unless you choose DoH, exactly as it would be without AdShield.
* Downloaded lists come from third parties; AdShield validates their shape and integrity-at-rest but cannot attest to their content. The phishing list aggregates feeds with non-commercial terms.

## Privacy

No analytics, advertising or crash-reporting SDKs; no location, contacts, storage, phone or ad-ID access; `allowBackup=false` and data-extraction rules exclude everything; cleartext traffic and user CAs are disallowed. A JVM test (`PrivacyPolicyTest`) fails the build if a forbidden permission, analytics dependency, TLS-weakening API, unexpected remote host or a default route is introduced. See the in-app Privacy policy for the exact metadata processed.

## License

Application code: Apache-2.0 (add the `LICENSE` file for your distribution). Third-party filter lists keep their own licenses, listed in the app (Blocklists and About screens).
