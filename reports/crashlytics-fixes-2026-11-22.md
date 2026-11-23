# Crashlytics library fixes — 2026-11-22

## Status and authorization

The user asked for the two libraries named in the fleet triage to be fixed and
released, then for every finding to be fixed in the best way. Releasing this plugin
(tag and push to JitPack) was explicitly authorized for this repository only.

Nine fleet findings were traced to this plugin: five `SoundManager: Failed to load
music` reports and four `Error loading pixmap: Image not of any known type, or
corrupt` reports. Firebase is only changed through
`crashlytics-ledger.py close --write`.

## What the findings had in common

Both symptoms end in a decoder rejecting bytes that came out of the decrypt path.
Before this change the runtime could not tell an intact asset from a damaged one:

- The header was `[magic 4][IV 16]`. AES-128-CTR is length preserving, so the
  plaintext length was recoverable but never stored, and nothing checked it.
- A truncated file decrypted into a shorter stream, and a padded file decrypted
  into a longer one. Both reached `Pixmap`/the audio backend as plausible-looking
  garbage, and the app reported the decoder's generic message.
- The build never confirmed that what it wrote could be read back, so a broken key
  derivation or a short write could only surface after a user installed the app.
- Audio copies were written in place and handed to the backend immediately, so a
  reader could open a half-written file.

## The change

**Asset format (breaking, `AesFileEncryptor`).** The header is now
`[magic 4][plaintext length 4][IV 16]`. `decrypt` compares the stored length with
the ciphertext length and raises `AssetCorruptionException` naming the asset and
both sizes. `isWellFormed` lets the build recognise an asset that carries the magic
but not the invariant, which is a stale artefact from an older plugin version or a
truncated file.

**Build-time round trip (`EncryptAssetsTask`).** Every asset it encrypts is decrypted
back and compared with its source; a mismatch fails the build with the asset path.
A stale in-place Android merge directory now fails with "encrypted but not in the
current asset format … Clean the build and rebuild" instead of shipping.

**Audio materialisation (`CryptorAudioWrapper`).** Decrypted audio is written to a
sibling `.part` file, size-checked, then renamed into place, so the backend is never
handed a partial file. `newSound`/`newMusic` invalidate a rejected copy and rebuild
it once before the caller's fallback runs.

**Diagnostics (`CryptorDiagnostics`).** Opt-in `-Dcryptor.diagnostics=true` logs each
asset's sizes and decrypt outcome. The failure path is already covered without it:
`AssetCorruptionException` carries the asset path and both sizes in its message, so
an Android report is actionable through the normal Crashlytics path.

## Releases

| Tag | Commit | Note |
|---|---|---|
| `v1.9.27` | `13b4600` | The fix above. **Superseded** — the injected runtime class set was not extended, so a consumer release build failed on unresolved `AesFileEncryptor$AssetCorruptionException` / `CryptorDiagnostics` references. |
| `v1.9.28` | `4ba6e3f` | The released version. Copies every injected runtime class and fails loudly when one is missing. |
| `v1.9.29` | pending | Prevents short magic-prefixed assets from passing as plaintext, shares Android/JVM format validation, and hardens locale-safe key derivation and concurrent audio cache publication. |
| `v1.9.30` | pending | Serializes non-iOS audio cache invalidation with materialization so invalidation cannot delete a newly rematerialized file. |

`v1.9.27` was not re-tagged: JitPack builds tags immutably, so a new tag was the
only honest way to publish the corrected class set.

The regression was caught by `:lwjgl3:releaseSmokeDesktop` in SamsWorld2, not by the
plugin's own tests, because those tests run against the plugin's classpath rather
than the injected output. The copy list now asserts on a missing resource.

## Verification

| Check | Result |
|---|---|
| Plugin unit tests (JDK 21) | 30 tests, 0 failures, including truncated and padded asset rejection and the audio rebuild-once path |
| JitPack `v1.9.28` | build `ok`, JDK 21, both modules published |
| SamsWorld2 `:android:assembleRelease` | ok; 2,386 configured assets, 0 without magic, 0 with a bad header |
| SamsWorld2 `:lwjgl3:releaseSmokeDesktop` | "obfuscated jar booted and reached level 1"; no `missing_rules.txt`, no unresolved-class warnings |
| Other six consumers `:android:assembleRelease` | all ok |

Asset header verification per consumer (magic present, stored length equals
ciphertext length):

| App | Assets checked | No magic | Bad header |
|---|---:|---:|---:|
| SamsWorld2 | 2,386 | 0 | 0 |
| SamsWorld | 228 | 0 | 0 |
| ZacksWorld | 229 | 0 | 0 |
| SamsLevelMaker | 209 | 0 | 0 |
| ZacksLevelMaker | 211 | 0 | 0 |
| MakeWords | 9 | 0 | 0 |
| JetPackRider | 18 | 18 | 0 |

JetPackRider packages plaintext on purpose (`cryptor { enabled = false }`), which is
why none of its assets carry the magic.

## Residuals

- A runtime key that differs from the build key still decrypts to garbage of the
  correct length, which the length check cannot see. `cryptorKeyCheck` guards the
  build side; SamsWorld still ships the public default key `DEADBEEFCAFEBABE` and has
  no release-key guard of its own.
- `CryptorDiagnostics` is a JVM system property, so it is reachable on desktop and
  iOS but not on Android. The exception message is the Android evidence path.
## v1.9.29 addendum

Build and runtime path/extension normalization now uses `Locale.ROOT`. Runtime
classification treats any matching magic prefix as encrypted, including truncated
headers, while Android and JVM builds share the same current-format validation and
round-trip helper. Audio cache publication uses unique synced sibling files, with
serialized desktop materialization and iOS cache invalidation on one retry.

## v1.9.30 addendum

Non-iOS audio invalidation now removes the cached entry and deletes its file while
holding the same `audioFileCache` monitor used by materialization. This prevents an
invalidation from deleting a replacement file published concurrently for the same
asset. A focused concurrency test verifies invalidation waits for that cache lock and
then removes the cached copy.
