# Research roadmap: Zenyard and RevEng.AI blog techniques

What the two vendors' published threat research detects, what reportal
already covers, and what is left to build.  Swept 2026-09-16 over the full
public indexes (11 Zenyard posts across 2 index pages, 10 RevEng.AI posts
across 2 index pages), each post mined for statically-detectable signals
only: packers, obfuscation tricks, anti-analysis checks with named APIs,
instructions, strings or constants, C2 patterns, crypto and string-encoding
tricks, and YARA-ready literals.  Behavioral, dynamic and attribution
material is out of scope for a static portal and is not listed.

Status vocabulary: **Covered** (a scan, rule or surface answers it today),
**Partial** (the mechanism exists but the signal family is missing),
**Open** (nothing answers it).  Every Open row names the module it lands
in and the evidence post.

## 1. Anti-analysis instruction tricks: Partial

Zenyard's SIDT-keyed RAT and Petite-VB6 posts name a whole family:
`SIDT`/`SGDT`/`SLDT` reads, `CPUID` hypervisor-bit checks, `RDTSC` timing,
`IN`/`OUT` port probes (0x4F, 0xEF, 0x93, 0x19, 0x3D, 0xA8, 0xFD),
`FNSTENV`/`FXSAVE` FPU-state validation, `INT3` traps, `LOCK`-prefixed
canary writes, segment-register abuse.  reportal's hardening
`anti-analysis` table matches disassembly mnemonics as string evidence
and already covers `rdtsc` (`timing-check`) and port probes
(`io-port-probe`).

Open, all in `hardening.py` string rules (status: `io-port-probe`,
`cpu-state-probe`, `int3-trap` and `lock-canary` shipped):

- `cpu-state-probe`: `SIDT`, `SGDT`, `SLDT`, `CPUID`, `FNSTENV`,
  `FSTENV`, `FXSAVE`, `FSAVE` mnemonics in disassembly text.
  **Status: shipped.** Evidence: [SIDT-keyed RAT part 1](https://www.zenyard.ai/blog/sidt-keyed-rat-analysis-part-1),
  [Petite VB6 part 1](https://www.zenyard.ai/blog/environmental-entropy-port-0x4f-petite-vb6-rat-part-1).
- `int3-trap`: `INT 3` / `int3` breakpoint traps, including the
  single-step (`PUSHF`/`POPF`, `0x100` flag) handling shape.
  **Status: shipped.**
- `lock-canary`: `LOCK`-prefixed integrity write/check pairs.
  **Status: shipped.** Evidence: SIDT-keyed RAT part 1.

## 2. Environment-derived crypto constants: Partial

Both RAT posts publish stable constants: session tag
`tag = (x + 0x20F645EA) & 0xFFFFFF00 | 0x99`, key transform `ESP ^
0x7F99CAC2`, RC4-like S-box base `0x5F` / stream start `0x78`,
canary `0x8B8F9397`, mask `0x478CCC4B`.  reportal's crypto scan
matches AES/SHA tables plus name/import matching; it has no
family-constant table.

Open, in the crypto scan's constant table (reportal-side: the engine
table needs full 256-byte tables, so short family constants live as a
`constants` evidence kind in `filetypes.py` with a `min_constants`
coincidence threshold):

- Tag/key/canary constants above as byte signatures with their LE
  encodings (`EA 45 F6 20`, `C2 CA 99 7F`, `97 93 8F 8B`,
  `4B CC 8C 47`).  **Status: shipped** as the `Paranoiac-RAT-family`
  packer row (`min_constants=3`, confidence low).
  Evidence: [VB6 part 2](https://www.zenyard.ai/blog/environmental-entropy-port-0x4f-c2-detection-part-2).

## 3. String-encoding and staging tricks: Covered

XOR 0x2E attack strings and Salsa20/ChaCha `expand 32-byte k` markers
(NeTiS posts), base64 blob staging (LinPEAS dropper post),
`cf_clearance` cookie reuse: covered by the secrets entropy scan, the
`embedded-payload` kind, and the threat URL/domain extractors.
Evidence: [NeTiS part 2](https://www.zenyard.ai/blog/netis-cloudflare-aware-c2-beaconing-part-2),
[LinPEAS dropper](https://www.zenyard.ai/blog/pipe-fed-linpeas-go-dropper-peass-ng-memory).

## 4. C2 template strings: Partial

DDoS flood templates (`Content-Length: 10485760`,
`PRI * HTTP/2.0` preface, `M-SEARCH * HTTP/1.1`, memcached `stats`
probe), raw-TCP newline framing, u16 length prefixes, session magics
(`0x0B6F0B73`, connect header `0x73C0`).  reportal's protocols and
behavior tables cover the socket APIs and flood verbs generically but
not these exact templates.

Shipped:

- Named flood-template literals as a `ddos-template` behavior rule
  (`behavior.py` networking domain).
- `NeTiS-Gafgyt-family` filetype row: session magic, connect header
  and the 256-bit key as byte constants (`min_constants=2`).
  Evidence: NeTiS part 2.

Still open: u16 length-prefix framing detection (needs disassembly
operand analysis, engine-side).

## 5. IoT/multi-arch staging markers: Open

`main_mips`/`main_arm7`/etc. filename clusters, `/root/dvr_gui/`
staging paths, `httpd`/`telnetd`/`dropbear` process-masquerade names,
`wget`/`curl`/`ftpget`/`tftp` downloader loops.  reportal has no IoT
marker table; file-path IOCs extract the strings but never classify
them.

Open, new small table (mirror of `filetypes.py` runtime rows):

- `iot-markers`: masquerade names, staging dirs, downloader names,
  multiarch filename cluster.  **Status: shipped** as the `iot-dropper`
  rule in the `behavior.py` execution domain (string literals only;
  generic paths like `/tmp` deliberately excluded).  Evidence: [NeTiS part 1](https://www.zenyard.ai/blog/netis-iot-botnet-gafgyt-mips-analysis-part-1).

## 6. Reflective loading and sparse IAT: Covered

Embedded MZ images, `GetProcAddress`-only resolution, empty IAT,
`VirtualProtect` W+X flips: covered by the filetype packer rows, the
hardening sparse-import heuristic, and the `dynamic-loading`
capability.  Evidence: VB6 part 1, Symbiote posts.

## 7. RevEng.AI research: mostly model-side, one portable item

WilBERT/Ventris (embedding models), AI decompilation, CPU-Z backdoor
hunting at scale, KorPlug/LummaStealer campaign analysis, StealC
string-decoding automation, kernel-driver vuln research
(CVE-2024-41498): the models and the scale are hosted-only.  The
portable item is StealC-style string decoding (stack-string and
XOR-decode loops recovered statically).  Evidence: [StealC IDAPython post](https://reveng.ai/blog/automating-string-decoding-in-malware-analysing-stealc-v1-with-idapython).

- Decoded-string recovery: single-byte XOR and stack-built strings
  surfaced beside the strings panel.  **Status: shipped** as
  `user_strings.decoded_strings`, a stored-only NASM text scan on
  `GET /api/functions/<id>/strings`.  No engine work; a function with
  no cached listing yields an empty `decoded` half.

## Deliberately out of scope

Dynamic-only behavior (reconnect cadence, traffic shaping, PRNG+time
nonce mixing, hang-on-error FSMs), attribution judgments, and sample
specifics (C2 addresses, per-sample keys, CLI hints).  A static portal
records these as IOCs when they appear as literals; it does not
reproduce the dynamic analysis that found them.

## Feed maintenance

Re-sweep both indexes when new posts appear:
`https://www.zenyard.ai/blog` (2 pages) and `https://reveng.ai/blog`
(2 pages).  Mine for statically-detectable signals only; a post with
no new literal, mnemonic, API or constant adds no row.
