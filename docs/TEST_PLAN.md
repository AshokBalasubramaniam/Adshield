# AdShield test plan and results

## A. Automated tests

### A1. JVM unit and pipeline-integration tests — `./gradlew testDebugUnitTest`

Run without a device. Results are written to `app/build/reports/tests/testDebugUnitTest/index.html`.

| Suite | What it proves |
|---|---|
| `DomainNormalizerTest`, `DomainSetTest` | Syntax validation, label/length limits, suffix matching (no parent / sibling / look-alike matches), 100 000 lookups in a 200 000-entry set run in well under 2 s |
| `RuleParserTest` | hosts / plain / simple-Adblock syntaxes; cosmetic, wildcard, path and exception rules rejected; IP literals ignored (not counted as errors); random garbage never throws |
| `AdFilteringEngineTest` | Precedence (app allow ▸ global allow ▸ user block ▸ essential ▸ malware ▸ phishing ▸ tracker ▸ ad), per-app allow isolation, essential-domain protection incl. exact-only entries, aggressive streaming mode, cache invalidation on update |
| `DnsMessageTest` | A / AAAA / HTTPS parsing; blocked-answer construction (null address, NODATA, NXDOMAIN); rejects responses, multi-question, compression in question; truncation at every length; 20 000 random and 20 000 mutated inputs never throw; TTL parsing; EDNS size; TC truncation |
| `DnsCacheTest` | Re-addressing to the new transaction id, TTL expiry, TTL clamp, failures/zero-TTL not cached, negative caching, LRU eviction, per-type keys |
| `DnsQueryProcessorTest` | Blocked names never reach upstream; forward → cache; failures and timeouts → SERVFAIL and not cached; malformed → FORMERR/drop; unsupported opcode → NOTIMP; block-mode switch |
| `UpstreamLoopbackTest` | **Real sockets** against fake servers: UDP round trip, UDP→TCP fallback on truncation, server failover, bind hooks invoked per socket, unreachable server times out, DoH URL validation |
| `IpPacketTest` | IPv4/IPv6 UDP round trip with valid checksums (odd payload length), TCP SYN → RST with correct ack and checksum, fragment/length/IHL/extension-header rejection, 60 000 random and mutated packets never throw |
| `ListDownloaderTest` | https-only (no connection opened for bad URLs), redirect following, redirect-downgrade refusal, redirect loops, size cap from header and from stream, HTML error pages, tiny lists, server errors/resets, shrink guard keeps the old file, SHA-256 of stored bytes, IP-heavy lists accepted |
| `EndToEndFilteringTest` | Raw IPv4 packet → real list parsing → real engine and cache → raw reply packet; streaming protections; aggressive mode |
| `PrivacyPolicyTest` | Exactly 5 permissions; no location/contacts/storage/`QUERY_ALL_PACKAGES`/wake-lock/boot; cleartext and backup off, no user CAs; no analytics/ads/HTTP-client dependencies; no TLS-weakening APIs; no unexpected remote hosts; no default route or `allowBypass` |

### A2. Instrumented tests — `./gradlew connectedDebugAndroidTest` (device or emulator required)

`DatabaseInstrumentedTest`: seeding never overwrites user choices, built-in lists cannot be deleted, unique user rules, only disabled apps stored, counter upserts accumulate, reset clears everything. **Compiled in CI of this repo; not executed in the authoring environment.**

### A3. Static analysis

`./gradlew lintDebug lintRelease detekt` — see README "Verification status".

## B. Manual device test plan (required before release)

The authoring environment had no hardware virtualisation or physical device, so everything below is **not yet executed**. Record device, Android version and result for each line.

### B1. Core function
1. Fresh install → splash → onboarding → *Get started* (notification permission prompt on Android 13+).
2. Dashboard ON → notification permission (if needed) → system VPN dialog → *OK*. Expect: key icon in status bar, notification "Protection active", button turns teal, status "Protected".
3. Dashboard OFF. Expect: VPN key icon gone, notification gone, status "Not protected", internet unaffected.
4. Deny the VPN dialog. Expect: stays OFF, no error loop.
5. Kill the app from recents while ON. Expect: Android restarts the service (sticky); if not, dashboard shows OFF (never a stale ON).
6. Settings › Network › VPN: start another VPN app. Expect: AdShield shows "VPN permission was revoked…" and OFF.

### B2. Blocking verification (with protection ON, lists downloaded)
1. From a PC on the same network run `adb shell` and `nslookup doubleclick.net` / `nslookup ads.example` inside Termux or browse to `https://d3ward.github.io/toolz/adblock.html`. Expect blocked categories to be unreachable; normal sites load.
2. `nslookup example.com` resolves normally; second lookup is faster (cache).
3. Add `example.org` to *Custom blocks*; expect failure within ~1 s without restarting; remove it; expect recovery. Add a blocked domain to the *Allowlist*; expect it to resolve.
4. Confirm the dashboard counters increase only when lookups happen and match the stats screen. *Reset statistics* returns all to 0.
5. Toggle an app off in *Apps*; expect the VPN to re-establish within ~2 s and that app's lookups no longer count.

### B3. YouTube / JioHotstar (honesty check)
1. Play YouTube with and without AdShield on the same video, repeat 10 times. Record whether in-stream ads still play (expected: they do). The app's *Limited · not verified* wording must remain accurate for the tested version; update `AppCompatibility.kt` only with evidence.
2. Confirm playback, sign-in, and (if available) DRM-protected titles work with AdShield ON in default mode.
3. Turn on *Aggressive streaming mode*; record what, if anything, breaks. Turn it off again.

### B4. Network handling and leaks
1. Switch Wi-Fi ⇄ mobile data while ON; lookups keep working within a few seconds; *Network status* updates.
2. Airplane mode on/off; expect recovery without restarting AdShield.
3. IPv6-only (or NAT64) network if available; lookups still work.
4. Set a custom DNS app (e.g. `dig @8.8.8.8 ads.doubleclick.net` in Termux); expect it to be answered by AdShield (known-resolver capture ON) and blocked.
5. Android *Private DNS*: Off and Automatic → works; a specific hostname → the app shows a warning; record the actual behaviour.
6. Chrome *Secure DNS* ON: expect Chrome's own DoH to bypass filtering (documented limitation).
7. Check no traffic to unexpected hosts: use a packet-capture/firewall app or router logs; only list publishers, the chosen upstream/DoH, and the apps' own traffic should appear.

### B5. Battery and performance (≥ 24 h per scenario)
Measure with `adb shell dumpsys batterystats --reset` then after the run `dumpsys batterystats com.adshield` and Settings › Battery.
| Scenario | Record |
|---|---|
| Idle, protection ON, screen off | mAh / % drained, wakeups, CPU time |
| Typical use (browsing, social) | same |
| Heavy DNS (open 20 news sites) | peak CPU %, queries/min on the Battery guide screen, memory (`dumpsys meminfo com.adshield`) |
| With 1Hosts Lite enabled vs disabled | memory difference (expected ~25 MB) |
Pass criteria (suggested): idle drain indistinguishable from baseline within measurement noise; no wake locks held (`dumpsys power`); no persistent CPU use when idle.

### B6. Lifecycle and recovery
1. Reboot with Always-on VPN enabled → service starts. Without Always-on → AdShield stays OFF (no boot receiver by design).
2. Revoke VPN consent in system settings while ON → clean stop and error message.
3. Force-stop → restart → dashboard shows OFF; ON works.
4. Low-memory kill (`adb shell am kill com.adshield`) → sticky restart honoured only if protection was ON.
5. Rotate device/process death during list download → no corrupt list (atomic replace), integrity check passes on next start.

### B7. Release validation checklist
- [ ] `./gradlew assembleRelease` signed with the release keystore; `apksigner verify --print-certs` OK
- [ ] `aapt2 dump permissions` on the release APK shows only the 5 declared permissions (also enforced at build time by `verifyReleasePermissions`)
- [ ] Install on API 29, 31, 33, 34, 36 devices; run B1–B4 on each
- [ ] Google Play: complete the *Foreground service – special use* declaration if publishing there
- [ ] `docs/DEPENDENCY_REPORT.md` regenerated on the release commit; no unresolved advisories
- [ ] Privacy policy text in-app matches the shipped behaviour
