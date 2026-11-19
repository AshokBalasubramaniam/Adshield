# YouTube advertising: investigation and root-cause analysis

## 0. Evidence level (read first)

| Kind of evidence | Status |
|---|---|
| Code audit of the whole existing implementation | ✅ done (section 2) |
| Unit and pipeline tests of every change | ✅ done (see `TEST_PLAN.md`) |
| Observation of the real YouTube app's DNS behaviour on a phone | ✅ **done once, on one device, for 4 short runs** (section 7). Android 17 (API 37), Samsung SM-S921B, YouTube 21.45.82 (system app, updated), AdShield debug build. |
| Measurement of whether YouTube ads appear with/without AdShield | ❌ **not done.** Section 7 records what was seen in 4 short runs; that is not a measurement and no ad-removal rate is claimed. No with/without-AdShield comparison exists yet. |

Statements are labelled **[code]** (read in the source, certain), **[test]** (reproduced by an automated test), **[design]** (follows from how Android/YouTube/DNS work, high confidence) or **[unverified]** (plausible, needs more device evidence) or **[device]** (observed on the test phone, one device only). The diagnostic log built in this change exists to turn the unverified items into evidence (section 6).

## 1. The answer to "why do some YouTube ads still appear?"

**The dominant cause is architectural and cannot be fixed by DNS filtering [design].** A DNS filter decides, per host name, whether the phone may learn that host's address. It sees nothing about what is sent over the connection afterwards. YouTube delivers most ads in ways where the host name is identical to the host serving the video or the page data:

| Delivery method | Host seen in DNS | Can DNS filtering separate it? | What AdShield does |
|---|---|---|---|
| Separate third-party ad domains (`doubleclick.net`, `googlesyndication.com`, `googleadservices.com`, `2mdn.net`) | dedicated ad host | **Yes** | Blocks (bundled list + downloaded lists) |
| Independent ad / measurement requests to separate hosts | separate host | **Yes, host by host** | Blocks listed hosts only. No keyword guessing [test: `KeywordSafetyTest`] |
| Tracking / analytics (`google-analytics.com`, `app-measurement.com`) | separate host | **Yes** | Blocks |
| YouTube first-party ad infrastructure (ad placements returned inside the player/API responses) | `www.youtube.com`, `youtubei.googleapis.com`, the same hosts as search, comments, sign-in and the player | **No** | Cannot block without breaking YouTube |
| Server-side ad insertion (ad stitched into the stream) | `*.googlevideo.com`, same as the video | **No** | Cannot block without breaking the video |
| Ads served with the video | `*.googlevideo.com` | **No** | Same |
| Creator sponsorships | none (inside the video) | Not a network ad | Nothing to do |

Consequence: pre-roll, mid-roll and post-roll ads that use the last four rows **will keep appearing** with any DNS-only filter. Which ads a given video gets, and by which route, is decided by YouTube's servers per video and per session, which explains "some videos show ads, others don't" and "behaviour changes between sessions" **[design]**. AdShield does not and cannot influence it. The app states this plainly (YouTube protection screen, Apps compatibility card, README).

What was **not** done, on purpose: blocking `googlevideo.com`, `youtube.com` or `youtubei.googleapis.com`; modifying the app; injecting scripts; intercepting or decrypting HTTPS; changing manifests; touching DRM or Premium. Each would break playback or violate your constraints, and none would be "ad blocking through the supported network filtering architecture".

## 2. Audit of the existing implementation

| Area | Finding | Evidence | Severity | Status |
|---|---|---|---|---|
| VpnService / forwarding | Only `/32` and `/128` DNS routes; no general packet forwarding exists by design. Interface rebuilds on per-app change; recovery with back-off. | [code] `AdShieldVpnService`, `PrivacyPolicyTest` | OK | unchanged |
| DNS parser | Strict bounds checks; no crash on random/mutated input (tens of thousands of cases). | [test] `DnsMessageTest`, `IpPacketTest` | OK | extended (CNAME parser fuzzed) |
| **CNAME handling** | Only the queried name was filtered. A clean name that is an alias for a listed tracker/ad host ("CNAME cloaking") was allowed. | [code] old `DnsQueryProcessor`; [test] `CnameFilteringTest` | **Medium** (filtering gap) | **Fixed** |
| **TCP DNS** | Every TCP SYN was answered with RST, so a client that got a truncated UDP answer could not retry. | [code] old `TunnelLoop` line `Syn ->` | **Medium** (intermittent resolution failures for large answers) | **Fixed** (minimal TCP responder) |
| Truncation | Answers larger than the client's UDP buffer are truncated (TC=1). Correct, but pointless without TCP. | [code] | Medium | Fixed via TCP DNS |
| DNS cache | Allowed answers were cached by TTL; filter ran before the cache, so rule changes applied to the *queried name* immediately. But aliases inside cached answers were never re-checked. | [code] | Low | **Fixed**: cache stores CNAME targets and re-checks them on every hit [test] |
| Domain matching | Whole-label suffix matching over hash sets; no substring or keyword matching. | [test] `DomainSetTest`, `KeywordSafetyTest` | OK | unchanged |
| Decision attribution | A block recorded only a category. It was impossible to say *which list or rule* blocked a host, which is exactly what is needed to debug "a bigger list broke playback". | [code] | **Medium** (diagnosability) | **Fixed**: per-list sets, decision carries rule + list id [test] |
| Blocklist updates | HTTPS-only, size cap, shape check, shrink guard, atomic replace, SHA-256 re-verified at load. | [test] `ListDownloaderTest` | OK | unchanged |
| Allowlist / per-app | Global and per-app allow rules work. Per-app *rules and statistics* depend on Android revealing the socket owner. | [code] | Info | see next row |
| **Attribution give-up** | `AppUidResolver` stopped trying forever after 200 unattributed lookups. If YouTube resolves names itself (some apps do), later lookups would never be attributed. | [code] | **Medium** (per-app YouTube features silently dead) | **Fixed**: keeps probing 1 in 20 |
| YouTube package detection | None existed. | [code] | Medium (feature missing) | Added (`com.google.android.youtube`, version, provenance) |
| YouTube-specific visibility | None: no log, no per-rule explanation, no bypass signals. | [code] | Medium | Added (diagnostics screen) |
| Streaming protection | One switch covered YouTube and Hotstar together. | [code] | Low | Split: separate YouTube profile (Safe / Aggressive) |
| Network lifecycle | `NetworkCallback` tracks the physical network; upstream rebuilt and cache cleared on change. | [code] | OK | unchanged; **not yet exercised on a device** |
| Foreground service | `specialUse` type, immutable PendingIntents, bounded stop wait. | [code] | OK | unchanged |
| Battery | No wake locks, boot receiver or scheduler (verified in the merged manifest by a build task). | build task | OK | unchanged |
| DNS leak handling | Upstream bound to the physical network; known public resolvers captured; TCP/853 and TCP/443 to them refused. Hard-coded *unknown* resolvers and in-app DoH cannot be seen. | [code] | Info | Bypass **signals** now counted and shown |
| Private DNS | Strict mode detected and warned; Automatic falls back to our plain DNS. | [code] | Info | unchanged; **behaviour on a device unverified** |
| Exported components | Activity (launcher) and `VpnService` (system must bind it; protected by signature permission `BIND_VPN_SERVICE`, so other apps cannot start/stop/bind it). | [code] manifest | OK | unchanged |

## 3. Why "increasing blocklist rules sometimes breaks playback"

[design] + [code]: large public lists contain first-party hosts of big services (an earlier inspection of the StevenBlack unified hosts file found `videoads.hotstar.com`, `service.hotstar.com` and `ads.youtube.com`, and its maintainers keep commented-out entries such as `redirector.googlevideo.com` annotated "affects video playback"). A host that carries ad requests *and* a function the app needs cannot be blocked without loss. AdShield's safety net (never block video CDN, DRM, sign-in, YouTube first-party in the default profile) prevents the breakage, at the cost of not blocking those hosts.

Before this change a user could not tell which rule had broken something. Now each decision names the rule and list, the log can be filtered to "Problems" (blocked or failed playback-critical lookups), and an entry can be allowed with one tap. This is the workflow requirement in section 6 of the brief: identify the rule, check the host is essential, add a narrow exception, retest, document the trade-off.

## 4. What changed (and what each change is expected to do)

| Change | Expected effect on YouTube ads | Expected effect on reliability |
|---|---|---|
| CNAME-aware filtering | Blocks ad/tracker hosts hidden behind innocent aliases (rare for YouTube itself; common on websites) | none |
| TCP DNS | none | Removes a failure mode for large DNS answers |
| Per-list attribution | none | Makes broken-playback rules findable |
| YouTube profile + diagnostics + bypass signals | none directly: they measure, they do not block | Makes every claim checkable |
| Attribution probing | none | Per-app features keep working if YouTube uses its own resolver |

**Honest expectation:** after this change, the number of YouTube ads is expected to be essentially unchanged for ads delivered through the last four rows of the table in section 1. The gains are in correctness, transparency and the ability to find concrete, evidence-based additional rules.

## 5. What a further improvement would require

Only a host that is (a) separate from video/API hosts, (b) observed in real YouTube traffic, and (c) not required for playback can be added safely. No such host beyond those already covered by the bundled and public lists is known from this investigation, so **no blocklist entries were added**. Adding guessed hosts would be the "random blocklist modification" the brief rules out. The diagnostic log is the instrument for finding real candidates.

## 6. How to produce the missing evidence

1. Reconnect a phone with USB debugging, install a debug build (`./gradlew installDebug`), turn protection on.
2. In **More → YouTube protection** switch on *Record the diagnostic log*.
3. Play videos (the scenarios in `TEST_PLAN.md` §C), then **Export** the log.
4. Debug builds also mirror YouTube-related decisions to `adb logcat -s AdShieldDiag` for live observation (release builds contain no such logging).
5. Fill the result table in `TEST_PLAN.md` §C from the log and from what was actually seen on screen. Mark rows not executed as *not run*.

Questions this will answer: does YouTube's resolver traffic reach AdShield at all and is it attributable to the app; which hosts are looked up around an ad break; whether any of them is separate, non-essential and blocked; whether Private DNS or encrypted DNS hides lookups (bypass signals); whether any playback-critical lookup is ever blocked or fails.

## 7. On-device observations (2026-11-19)

Setup: AdShield debug build, protection ON, tunnel verified on the phone (`tun0` with `10.111.222.1/32`, routes only `/32` and `/128` to the virtual DNS and captured resolvers, **no default route**, foreground service type `specialUse` running). Network: Wi-Fi per the status bar. Android Private DNS was **strict, `dns.adguard.com`** (the user's own setting, left untouched). Lists: the bundled `seed-ads` / `seed-trackers` appear in decisions; the downloaded lists' version was not read. Videos were launched by `adb` intent in the official app with media volume muted and restored. Lookups come from AdShield's debug-only `AdShieldDiag` log.

| Run | Video | YouTube lookups seen | Of which blocked | Playback | Ad seen on screen |
|---|---|---|---|---|---|
| R1 | "Me at the zoo" (19 s) | 36 | **0** | Normal; subtitles, comments, Shorts loaded | None in the 2 screenshots reviewed (12 s, 27 s) |
| R2 | Despacito | 4 | **0** | Normal | None at 7 s (16 s / 30 s screenshots not reviewed) |
| R3 | Gangnam Style | 4 | **2**: `googleads.g.doubleclick.net` (A and AAAA), rule `doubleclick.net`, list `seed-ads` | Video played; **related-video area below the comments stayed empty** at 7 s and 30 s | None at 7 s and 30 s |
| R4 | Gangnam Style, repeat | 4 | **0** | Video played; related-video area empty again | not reviewed |

What this establishes **[device]**:

1. **Lookups reach AdShield and are attributed to the YouTube app** (`app=com.google.android.youtube`). My earlier statement that Android "usually" hides the app behind the system resolver was **wrong for this device**; documentation and in-app text were corrected.
2. **With strict Private DNS set to `dns.adguard.com`, AdShield still received YouTube's lookups.** My hypothesis that strict Private DNS bypasses the VPN's DNS was **not confirmed** on this device. Why Android behaved this way was not investigated (the platform dumps needed are not readable from the shell). Behaviour on other Android versions is unknown, so the warning text now says "may". Whether the user's *earlier* observations of blocked ads came from AdShield or from AdGuard DNS is **not determined**.
3. Every `googlevideo.com` host (8 distinct), `www.youtube.com`, `youtubei.googleapis.com`, `s.youtube.com`, thumbnails and avatars were **allowed**: no playback-critical lookup was blocked or failed in any run.
4. In R1, R2 and R4 YouTube did **not look up any separate ad or tracking host**, so there was nothing for DNS filtering to block. In R3 it looked up one (`googleads.g.doubleclick.net`) and AdShield blocked it. Blocking that lookup is **not** evidence that an ad was removed (none was visibly present either way).
5. The empty related-video area in R3/R4 is **unexplained**. It occurred in R4 with **no blocked lookup at all**, so it is not explained by the one block in R3. It was not seen in R1/R2. Whether it is caused by AdShield, by the way the video was launched, or by YouTube itself is **unknown**; it needs the A/B below.

Open test (needs the user, not run): same Gangnam Style video launched the same way with AdShield **off**, then **on**; compare the related-video area. If it is empty with AdShield off too, AdShield is not the cause.

Not exercised on the device in this session: TCP DNS (no truncated answer occurred), CNAME blocking in real traffic (no CNAME-based decision occurred), IPv6-only networks, network switching, Private DNS Off/Automatic, live streams, mid-roll and post-roll ads, a YouTube update. All remain *not run* in `TEST_PLAN.md`.
