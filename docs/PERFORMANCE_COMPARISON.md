# Performance comparison

Micro-benchmark `app/src/test/kotlin/com/adshield/perf/EngineBenchmarkTest.kt`, run on the **same machine** against (a) the commit before this work (`HEAD` worktree, labelled *before*) and (b) the working tree. It uses only APIs present in both versions. JVM 17 (OpenJDK, desktop), 200 000-rule list, warm-up then measured loop, allocation read from the thread's allocated-bytes counter. Four *before* runs, two *first-version* runs and two *optimised* runs were interleaved; the table shows medians. Generated 2026-11-19.

These are desktop-JVM micro-benchmarks of the pure-Kotlin filtering path. They are **not** phone measurements and say nothing about battery; they show relative cost and allocation of the code paths this work touched.

| Benchmark | Before | First version of this work | Optimised (final) | Δ time final vs before | Δ alloc final vs before |
|---|---|---|---|---|---|
| DnsParser.parseQuery | 75 ns · 128 B | 69 ns · 128 B (-7% time) | 72 ns · 128 B | -3% | +0% |
| engine.evaluate (miss, 200k rules, cold) | 630 ns · 855 B | 816 ns · 1107 B (+29% time) | 468 ns · 431 B | -26% | -50% |
| engine.evaluate (hit, 200k rules) | 604 ns · 556 B | 703 ns · 740 B (+16% time) | 464 ns · 368 B | -23% | -34% |
| engine.evaluate (repeat, decision cache) | 26 ns · 0 B | 28 ns · 0 B (+6% time) | 37 ns · 0 B | +42% | n/a |
| processor: blocked name end-to-end | 1063 ns · 816 B | 1136 ns · 816 B (+7% time) | 1113 ns · 816 B | +5% | +0% |
| processor: allowed, first resolve (miss) | 3648 ns · 2752 B | 3593 ns · 2850 B (-2% time) | 3356 ns · 2585 B | -8% | -6% |
| processor: allowed, cache hit | 2754 ns · 2120 B | 2847 ns · 2116 B (+3% time) | 3106 ns · 2116 B | +13% | -0% |

## What the numbers show

* **The first version of the new code was slower** on the rule-lookup path (about +30% time and allocations for a cold lookup). Cause: the per-list sets and the extra essential-domain set each re-walked and re-allocated the domain's suffix substrings. This regression was found by this benchmark, not assumed.
* **Fix:** the suffix list of a name is now built once per decision and shared by every set probed (`DomainSet.Suffixes`), and iterator allocations were removed from the hot loop. Semantics are unchanged (`SuffixesTest` proves the shared and plain lookups agree for every case; the whole engine test-suite is unchanged).
* **Result:** the final code is faster and allocates less than the code before this work on cold lookups, even though it now does more (per-list attribution, YouTube profile, an extra protected set).
* The end-to-end `processor` rows include the new CNAME check (a parse of the answer section on resolve, and a re-check of cached CNAME targets on every cache hit). Measured: blocked path +5%, first resolve −8%, **cache hit +13% (+350 ns)**. Identical *before* runs differ by about ±10% on this machine, so the +5% and −8% rows are not distinguishable from noise, and the +13% on cache hits is at the edge of it. The expected cause is the per-hit CNAME re-check; it is the price of re-applying rule updates to cached answers, and it was not optimised further.
* Repeat lookups are served by the decision cache with no allocation before and after. The final run shows 37 ns against 26 ns before (+11 ns); that path was not changed, the 28 ns of the first-version runs suggests this is run-to-run variation, but it was not investigated further.

## Raw runs

```
label=before-1  jvm=17.0.21.0.3  events=1604094
DnsParser.parseQuery                                78 ns/op       128 B/op
engine.evaluate (miss, 200k rules, cold)           619 ns/op       855 B/op
engine.evaluate (hit, 200k rules)                  547 ns/op       556 B/op
engine.evaluate (repeat, decision cache)            27 ns/op         0 B/op
processor: blocked name end-to-end                1012 ns/op       816 B/op
processor: allowed, first resolve (miss)          3696 ns/op      2745 B/op
processor: allowed, cache hit                     2565 ns/op      2108 B/op

label=before-2  jvm=17.0.21.0.3  events=1604094
DnsParser.parseQuery                                68 ns/op       128 B/op
engine.evaluate (miss, 200k rules, cold)           681 ns/op       879 B/op
engine.evaluate (hit, 200k rules)                  620 ns/op       556 B/op
engine.evaluate (repeat, decision cache)            26 ns/op         0 B/op
processor: blocked name end-to-end                1181 ns/op       816 B/op
processor: allowed, first resolve (miss)          3299 ns/op      2760 B/op
processor: allowed, cache hit                     2919 ns/op      2132 B/op

label=before-3  jvm=17.0.21.0.3  events=1604094
DnsParser.parseQuery                                77 ns/op        99 B/op
engine.evaluate (miss, 200k rules, cold)           638 ns/op       855 B/op
engine.evaluate (hit, 200k rules)                  588 ns/op       556 B/op
engine.evaluate (repeat, decision cache)            32 ns/op         0 B/op
processor: blocked name end-to-end                1055 ns/op       816 B/op
processor: allowed, first resolve (miss)          3774 ns/op      2732 B/op
processor: allowed, cache hit                     2760 ns/op      2100 B/op

label=before-4  jvm=17.0.21.0.3  events=1604094
DnsParser.parseQuery                                73 ns/op       128 B/op
engine.evaluate (miss, 200k rules, cold)           623 ns/op       855 B/op
engine.evaluate (hit, 200k rules)                  628 ns/op       556 B/op
engine.evaluate (repeat, decision cache)            25 ns/op         0 B/op
processor: blocked name end-to-end                1071 ns/op       816 B/op
processor: allowed, first resolve (miss)          3600 ns/op      2766 B/op
processor: allowed, cache hit                     2748 ns/op      2132 B/op

label=after-1  jvm=17.0.21.0.3  events=1604094
DnsParser.parseQuery                                66 ns/op       128 B/op
engine.evaluate (miss, 200k rules, cold)           920 ns/op      1119 B/op
engine.evaluate (hit, 200k rules)                  752 ns/op       740 B/op
engine.evaluate (repeat, decision cache)            29 ns/op         0 B/op
processor: blocked name end-to-end                1170 ns/op       816 B/op
processor: allowed, first resolve (miss)          3370 ns/op      2851 B/op
processor: allowed, cache hit                     2596 ns/op      2116 B/op

label=after-2  jvm=17.0.21.0.3  events=1604094
DnsParser.parseQuery                                73 ns/op       128 B/op
engine.evaluate (miss, 200k rules, cold)           712 ns/op      1095 B/op
engine.evaluate (hit, 200k rules)                  655 ns/op       740 B/op
engine.evaluate (repeat, decision cache)            27 ns/op         0 B/op
processor: blocked name end-to-end                1102 ns/op       816 B/op
processor: allowed, first resolve (miss)          3816 ns/op      2850 B/op
processor: allowed, cache hit                     3098 ns/op      2116 B/op

label=after-3  jvm=17.0.21.0.3  events=1604094
DnsParser.parseQuery                                72 ns/op       128 B/op
engine.evaluate (miss, 200k rules, cold)           483 ns/op       431 B/op
engine.evaluate (hit, 200k rules)                  464 ns/op       368 B/op
engine.evaluate (repeat, decision cache)            46 ns/op         0 B/op
processor: blocked name end-to-end                1084 ns/op       816 B/op
processor: allowed, first resolve (miss)          3513 ns/op      2587 B/op
processor: allowed, cache hit                     3117 ns/op      2116 B/op

label=after-4  jvm=17.0.21.0.3  events=1604094
DnsParser.parseQuery                                73 ns/op       128 B/op
engine.evaluate (miss, 200k rules, cold)           454 ns/op       431 B/op
engine.evaluate (hit, 200k rules)                  464 ns/op       368 B/op
engine.evaluate (repeat, decision cache)            29 ns/op         0 B/op
processor: blocked name end-to-end                1143 ns/op       816 B/op
processor: allowed, first resolve (miss)          3199 ns/op      2584 B/op
processor: allowed, cache hit                     3095 ns/op      2116 B/op

```
