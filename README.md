# Cryptor-Gradle-Plugin

[![](https://jitpack.io/v/MRZ07/Cryptor-Gradle-Plugin.svg)](https://jitpack.io/#MRZ07/Cryptor-Gradle-Plugin)

A Gradle plugin that **encrypts all string literals and game assets at build time** using ASM bytecode transformation.
Strings and assets are decrypted transparently at runtime — fully offline, with zero source-code changes required.

Works with **any JVM Gradle project** (Kotlin, Java, multi-module) and has first-class support for **LibGDX** (Android + Desktop/lwjgl3).

---

## Table of Contents

- [How it works](#how-it-works)
- [Features](#features)
- [Requirements](#requirements)
- **[JVM / Kotlin Project](#-jvm--kotlin-project)**
  - [1. Register JitPack](#1-register-jitpack-in-settingsgradle)
  - [2. Apply and configure](#2-apply-and-configure)
  - [3. Store the key safely](#3-keep-the-key-out-of-version-control)
  - [What happens automatically](#what-happens-automatically)
  - [Multi-module projects](#multi-module-projects)
- **[LibGDX Project](#-libgdx-project)**
  - [Core only (recommended)](#core-module-only-recommended)
  - [settings.gradle with Android](#settingsgradle-for-libgdx-with-android)
  - [Optional: lwjgl3 module — with asset encryption](#optional-desktop-lwjgl3-module--asset-encryption)
  - [Optional: Android module](#optional-android-module)
- [Configuration Reference](#configuration-reference)
- [Available versions](#available-versions)
- [Internals](#internals)
- [Automatic exclusions](#automatic-exclusions)
- [Verifying the output](#verifying-the-output)
- [Limitations & security notes](#limitations--security-notes)

---

## How it works

### String encryption

```
Your source (.kt / .java)
        │
        ▼  compileKotlin / compileJava
   .class files  ←── only your own sources; libraries are never touched
        │
        ▼  encryptStrings task
        │
        │  1. Visit every LDC String instruction via ASM
        │  2. Compute per-string salt = murmur64(plaintext UTF-8 bytes)
        │  3. Encrypt with derivedKey = configKey XOR salt
        │  4. Store [8-byte salt | encrypted bytes] as ISO-8859-1 string literal
        │  5. Replace instruction with: INVOKESTATIC <obfClass>.<obfMethod>(String)
        │  6. Inject the key-patched decryptor class (obfuscated name)
        │
        ▼
   .class files  — no plaintext strings, unique key per string, decryptor named after your key
        │
        ▼  jar / dex / package as usual
```

The injected decryptor is **never named `StringDecryptor`** in the output.
Both the class name and method name are derived deterministically from your encryption key
(e.g. `ieuufi.ro(String)`), so every project gets unique names.
Each string is decrypted once on first use and cached — zero overhead on repeated access.

**Per-string salt:** every string is encrypted with its own derived key (`configKey XOR murmur64(plaintext)`).
Recovering the keystream for one string does not help decrypt any other string.

### Asset encryption

```
assets/  (raw)
    │
    ▼  encryptAssets task
    │  For each file with a supported extension:
    │    1. Derive master AES-128 key:  SHA-256(configKey)[0:16]
    │    2. Derive file key:            SHA-256(masterKey ∥ relativePath)[0:16]
    │    3. Generate random 16-byte IV (SecureRandom)
    │    4. Encrypt with AES-128-CTR
    │    5. Prepend header: [magic(4)] [IV(16)] [ciphertext]
    │       magic = SHA-256(masterKey)[0:4]  — unique per project key
    │  Audio / unsupported extensions: copied as-is
    ▼
build/encryptedAssets/  → wired directly into the jar task
```

---

## Features

- Zero source-code changes required
- Encrypts all Kotlin **and** Java compiled classes
- Runtime decryptor auto-injected with a **key-derived obfuscated name** — `StringDecryptor.decrypt` never appears in decompiled output
- **Per-string salt** — each string encrypted with `configKey XOR murmur64(plaintext)`; recovering one string does not expose others
- Debug builds skipped by default so stack traces stay readable during development
- Configurable 64-bit key per project
- Package exclusion list — Kotlin stdlib, JDK, and Android framework always excluded automatically
- **ProGuard/R8 compatible** — no keep-rule needed; ProGuard further renames the already-obfuscated decryptor
- **Asset encryption** — **AES-128-CTR** with per-file derived keys and random IV per file; known-plaintext attack cannot recover the key
- **Per-project magic header** — derived from `SHA-256(masterKey)[0:4]`; each project has unique file identification bytes — no fixed byte pattern to grep for
- **Obfuscated wrapper class names** — `CryptorFilesWrapper` and `CryptorAudioWrapper` are renamed to key-derived names at build time, just like the string decryptor
- **Arithmetic key veil** — the four AES key Int fields are injected as `VEIL XOR part` pairs, not raw constants; no single bytecode value reveals a key part
- **ProGuard-safe activation** — wrappers wired into `Gdx.files` / `Gdx.audio` via direct ASM bytecode injection into `create()` and `resume()`, not reflection

---

## Requirements

| Tool | Minimum version |
|------|----------------|
| Gradle | 8.x |
| Java | 11 |
| Kotlin | 1.9+ (if using Kotlin) |
| Android Gradle Plugin | 8.x (only for Android modules) |

---

# ☕ JVM / Kotlin Project

## 1. Register JitPack in `settings.gradle`

Only the `pluginManagement` block is needed for pure JVM projects — no `dependencyResolutionManagement` required.

```groovy
// settings.gradle (Groovy DSL)
pluginManagement {
    repositories {
        maven { url 'https://jitpack.io' }
        gradlePluginPortal()
        mavenCentral()
    }
    resolutionStrategy {
        eachPlugin {
            if (requested.id.id.startsWith('com.github.MRZ07')) {
                useModule("com.github.MRZ07:Cryptor-Gradle-Plugin:${requested.version}")
            }
        }
    }
}
```

```kotlin
// settings.gradle.kts (Kotlin DSL)
pluginManagement {
    repositories {
        maven("https://jitpack.io")
        gradlePluginPortal()
        mavenCentral()
    }
    resolutionStrategy {
        eachPlugin {
            if (requested.id.id.startsWith("com.github.MRZ07")) {
                useModule("com.github.MRZ07:Cryptor-Gradle-Plugin:${requested.version}")
            }
        }
    }
}
```

## 2. Apply and configure

```groovy
// build.gradle (Groovy DSL)
plugins {
    id 'org.jetbrains.kotlin.jvm' version '2.0.0'  // or 'java'
    id 'com.github.MRZ07.Cryptor-Gradle-Plugin' version 'v1.9.0'
}

cryptor {
    key = 0xDEADBEEFCAFEBABEL   // your 64-bit key — change this!
    skipDebug = true             // skip encryption on debug builds
}
```

```kotlin
// build.gradle.kts (Kotlin DSL)
plugins {
    kotlin("jvm") version "2.0.0"   // or id("java")
    id("com.github.MRZ07.Cryptor-Gradle-Plugin") version "v1.9.0"
}

cryptor {
    key.set(0xDEADBEEFCAFEBABEL)
    skipDebug.set(true)
}
```

## 3. Keep the key out of version control

Store the key in `local.properties` (add that file to `.gitignore`):

```properties
# local.properties
encryptor.key=DEADBEEFCAFEBABE
```

Read it in your build file:

```groovy
// Groovy
def props = new Properties()
file("local.properties").withInputStream { props.load(it) }
cryptor {
    key = Long.parseUnsignedLong(props['encryptor.key'], 16)
    skipDebug = true
}
```

```kotlin
// Kotlin
val localProps = java.util.Properties().apply {
    rootProject.file("local.properties").inputStream().use(::load)
}
cryptor {
    key.set(localProps.getProperty("encryptor.key").toLong(16))
    skipDebug.set(true)
}
```

## What happens automatically

| Step | What the plugin does |
|------|---------------------|
| After `compileKotlin` / `compileJava` | Runs `encryptStrings`, writes encrypted `.class` files to `build/encryptedClasses/` |
| `jar` task | Pulls from `encryptedClasses/` (not the original compile output) and includes the obfuscated decryptor class |
| Runtime | Each encrypted string is decrypted on first access and cached — no repeated work |

Your normal `./gradlew jar` or `./gradlew build` workflow is completely unchanged.

## Multi-module projects

Apply the plugin in each submodule you want to protect. Use the **same key** in every module — the obfuscated class/method name is derived from the key, so all modules will reference the same decryptor class name consistently.

```
my-app/
├── settings.gradle       ← pluginManagement with JitPack (once)
├── app/
│   └── build.gradle      ← apply plugin + key
└── lib/
    └── build.gradle      ← apply plugin + same key
```

---

# 🎮 LibGDX Project

## Core module only (recommended)

For LibGDX, **applying the plugin to `core` alone is enough** in most cases.
All game logic, asset paths, map names, and entity strings live in `core`.
The platform launchers (`android`, `lwjgl3`, `ios`) are thin bootstrap wrappers with very few strings.

```
MyGame/
├── settings.gradle       ← JitPack pluginManagement (see below for Android variant)
├── core/
│   └── build.gradle      ← ✅ apply plugin here — protects all game logic
├── android/
│   └── build.gradle      ← optional
└── lwjgl3/
    └── build.gradle      ← optional
```

`core` is a plain JVM module — use the [JVM setup](#-jvm--kotlin-project) above.

## settings.gradle for LibGDX (with Android)

Android projects need both `pluginManagement` **and** `dependencyResolutionManagement`:

```groovy
// settings.gradle (Groovy DSL)
pluginManagement {
    repositories {
        maven { url 'https://jitpack.io' }
        gradlePluginPortal()
        google()
        mavenCentral()
    }
    resolutionStrategy {
        eachPlugin {
            if (requested.id.id.startsWith('com.github.MRZ07')) {
                useModule("com.github.MRZ07:Cryptor-Gradle-Plugin:${requested.version}")
            }
        }
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        maven { url 'https://jitpack.io' }
        google()
        mavenCentral()
    }
}
```

## Optional: Desktop (`lwjgl3`) module — asset encryption

Apply the plugin to the `lwjgl3` module to enable encrypted asset loading. The plugin will:
1. AES-128-CTR encrypt all supported asset files at build time and include them in the fat JAR
2. Inject an obfuscated `CryptorFilesWrapper` into the JAR — a `Files` proxy that decrypts on-the-fly
3. ASM-patch `Game.create()` and `Game.resume()` to install the wrappers into `Gdx.files` and `Gdx.audio` — **no manual change needed**

```groovy
// lwjgl3/build.gradle
plugins {
    id 'com.github.MRZ07.Cryptor-Gradle-Plugin' version 'v1.9.0'
}

def localProps = new Properties()
file("../local.properties").withInputStream { localProps.load(it) }

cryptor {
    enabled = true
    key = Long.parseUnsignedLong(localProps['encryptor.key'], 16)
    skipDebug = true
    encryptAssets = true
    assetsDir = file('../assets')      // path to your game assets folder
}
```

The plugin detects a plain JVM module and wires the encrypted classes and assets into the `jar` task automatically.

## Optional: Android module

```groovy
// android/build.gradle
plugins {
    id 'com.github.MRZ07.Cryptor-Gradle-Plugin' version 'v1.9.0'
}
cryptor {
    key = Long.parseUnsignedLong(localProps['encryptor.key'], 16)
    excludePackages = ['com/google/', 'com/android/']
    skipDebug = true
}
```

The plugin hooks into `AndroidComponentsExtension.onVariants` and runs an `encryptStrings<Variant>` task for each build variant automatically.

> **iOS (RoboVM):** Asset encryption is **not supported** on iOS — RoboVM does not expose Gradle task hooks that allow intercepting the IPA asset packaging pipeline.
> **String encryption is fully active on iOS** because the encrypted `.class` files come from `core`, which is compiled on the JVM path and included in the RoboVM build via project dependency.

---

## Configuration Reference

All options go inside the `cryptor { }` block:

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `enabled` | `Boolean` | `true` | Master switch. Set to `false` to disable all encryption without removing the plugin block. |
| `key` | `Long` | `0xDEADBEEFCAFEBABE` | 64-bit config key. **Always override this.** Determines obfuscated names and is expanded to 128-bit AES key via SHA-256 for asset encryption. |
| `excludePackages` | `List<String>` | `[]` | Additional slash-separated package prefixes to skip (e.g. `['com/google/']`). Kotlin, JDK, and Android are always excluded. |
| `skipDebug` | `Boolean` | `true` | When `true`, debug build variants are not encrypted so stack traces remain readable during development. |
| `encryptStrings` | `Boolean` | `true` | When `true`, string literals in class files are encrypted with a per-string derived key. |
| `encryptAssets` | `Boolean` | `true` | When `true`, asset files in `assetsDir` are AES-128-CTR encrypted and the files wrapper is injected. Requires `assetsDir`. |
| `assetsDir` | `DirectoryProperty` | _(unset)_ | Path to the assets directory to encrypt. Must be set when `encryptAssets = true`. |
| `assetExtensions` | `List<String>` | see below | File extensions to encrypt. |

**Default `assetExtensions`:**
```
tmx  png  jpg  jpeg  atlas  pack  fnt  ttf  mp3  ogg  wav  map
```
`json` and `properties` are intentionally excluded — plain-text configs and tool-readable files should not be encrypted.

---

## Available versions

> **[https://jitpack.io/#MRZ07/Cryptor-Gradle-Plugin](https://jitpack.io/#MRZ07/Cryptor-Gradle-Plugin)**

| Version | Status | Highlights |
|---------|--------|------------|
| `v1.0` | stable | String encryption, decryptor injection, ProGuard-safe obfuscated names |
| `v1.1` | stable | Asset encryption (`encryptAssets`), `CryptorFilesWrapper`, magic-header guard |
| `v1.2` | stable | ProGuard-safe activation — ASM patches `create()` directly; no reflection |
| `v1.3` | stable | IDE-compatible asset encryption — raw assets on classpath, encrypted only in JAR |
| `v1.4` | stable | DSL renamed `cryptor {}`, audio encryption (mp3/ogg/wav), `enabled` master switch |
| `v1.5` | stable | `encryptStrings` flag, TTF font encryption |
| `v1.6.0` | stable | `CryptorAudioWrapper` — audio via temp file; full ProGuard/R8 on Android |
| `v1.6.1` | stable | `applyAndroid()` auto-sets `encryptStrings` and `injectFilesWrapper` |
| `v1.7.4` | stable | Android asset encryption; Gradle 9 compatibility; `CryptorFileHandle.map()` |
| `v1.7.6` | stable | Improved Android asset encryption ordering |
| `v1.7.8` | stable | Remove `json`/`properties` from default extensions; add `map` |
| `v1.8.0` | stable | **AES-128-CTR** replaces XOR for assets; per-file derived keys; random IV per file; split master key (`KEY_0..KEY_3`) |
| `v1.9.0` | ✅ **latest** | Wrapper class name obfuscation; per-string salt; arithmetic key veil; per-project derived magic header |

---

## Internals

### Plugin source layout

```
src/main/kotlin/
├── CryptorPlugin.kt         # entry point — wires tasks, derives all obfuscated names from key
├── CryptorExtension.kt      # DSL: enabled, key, excludePackages, skipDebug, encryptStrings, encryptAssets, assetsDir, assetExtensions
├── EncryptClassesTask.kt    # ASM transformation + decryptor/wrapper injection + create()/resume() patch
├── EncryptAssetsTask.kt     # AES-128-CTR encrypts asset files with per-file derived keys
├── AesFileEncryptor.kt      # AES crypto: key derivation, per-file key, encrypt, decrypt, per-project magic
├── CryptorFilesWrapper.kt   # Runtime Files proxy — injected and renamed; decrypts on read
├── CryptorAudioWrapper.kt   # Runtime Audio proxy — decrypts audio to temp file; ProGuard/R8 safe
├── XorEncryptor.kt          # String encrypt: salt = murmur64(plaintext), derivedKey = key XOR salt
└── StringDecryptor.kt       # Decryptor template — injected, renamed, and key-patched at build time
```

### Asset encryption pipeline (v1.8+)

```
assets/  (raw)
    │
    ▼  encryptAssets task
    │  1. masterKey  = SHA-256(configKey)[0:16]
    │  2. Per file:
    │     a. fileKey = SHA-256(masterKey ∥ relativePath)[0:16]
    │     b. IV      = SecureRandom 16 bytes
    │     c. magic   = SHA-256(masterKey)[0:4]  ← unique per project
    │     d. output  = magic + IV + AES-128-CTR(fileKey, IV, plaintext)
    │  3. Unsupported extensions: copied as-is
    ▼
build/encryptedAssets/  → wired into jar task; raw copies excluded
```

### CryptorFilesWrapper activation

After string encryption and wrapper injection, the plugin scans the output for the class extending `com/badlogic/gdx/Game` and prepends bytecode to both `create()V` and `resume()V`.
The wrapper class name is **obfuscated** (key-derived), so the bytecode below uses a placeholder:

```
// Gdx.files = new <obfFilesWrapper>(Gdx.files)
NEW     <obfFilesWrapper>
DUP
GETSTATIC  com/badlogic/gdx/Gdx.files
INVOKESPECIAL  <obfFilesWrapper>.<init>(Lcom/badlogic/gdx/Files;)V
PUTSTATIC  com/badlogic/gdx/Gdx.files

// Gdx.audio = new <obfAudioWrapper>(Gdx.audio)
NEW     <obfAudioWrapper>
DUP
GETSTATIC  com/badlogic/gdx/Gdx.audio
INVOKESPECIAL  <obfAudioWrapper>.<init>(Lcom/badlogic/gdx/Audio;)V
PUTSTATIC  com/badlogic/gdx/Gdx.audio
```

`resume()V` is synthesized if the `Game` subclass does not override it — needed on Android because `onResume()` resets `Gdx.files` and `Gdx.audio` to bare platform implementations.

### Key injection (arithmetic veil)

The AES master key is split across four `Int` fields (`KEY_0..KEY_3`) in the wrapper class.
Each is injected as an XOR pair — **neither constant alone is a key part**:

```
// Injected into <clinit> for each of i = 0..3:
LDC  VEIL_i            // unrelated-looking constant
LDC  VEIL_i XOR KEY_i  // another unrelated-looking constant
IXOR                   // → KEY_i at runtime
PUTSTATIC KEY_i
```

### Runtime decryptor

The decryptor reads the 8-byte salt prefix, derives the key, and decrypts:

```kotlin
object StringDecryptor {         // renamed at build time, e.g. → ieuufi
    private val KEY: Long = 0L   // patched with your real key

    @JvmStatic
    fun decrypt(encoded: String): String {   // renamed, e.g. → ro
        // First 8 chars = salt (little-endian Long = murmur64 of original plaintext)
        var salt = 0L
        for (i in 0 until 8) salt = salt or ((encoded[i].code.toLong() and 0xFF) shl (i * 8))
        val derivedKey = KEY xor salt
        val data = encoded.substring(8).toByteArray(Charsets.ISO_8859_1)
        return String(ByteArray(data.size) { i ->
            (data[i].toInt() xor ((derivedKey ushr ((i % 8) * 8)) and 0xFF).toInt()).toByte()
        })
    }
}
```

---

## Automatic exclusions

The following prefixes are always skipped — you do not need to add them to `excludePackages`:

| Prefix | Reason |
|--------|--------|
| `kotlin/` | Kotlin stdlib internals |
| `kotlinx/` | Kotlin coroutines / extensions |
| `java/` | JDK classes |
| `javax/` | JDK extension classes |
| `android/` | Android framework |
| `StringDecryptor` | Template class (safety guard) |
| _derived obf name_ | Injected decryptor (excluded dynamically per key) |

---

## Verifying the output

```bash
# Confirm no plaintext LDC String instructions remain in an encrypted class:
javap -c MyClass.class | grep 'ldc "'

# Confirm the decryptor reference uses the obfuscated name (not StringDecryptor.decrypt):
javap -verbose MyClass.class | grep 'Method.*String'
# Expected: something like  ieuufi.ro:(Ljava/lang/String;)Ljava/lang/String;

# Confirm no class named CryptorFilesWrapper exists (it is renamed per project key):
jar tf MyGame.jar | grep -i cryptor
# Expected: no output — wrapper is present under a key-derived name only

# Confirm the wrapper is wired into create() without reflection:
javap -c MyGame.class | grep -A 15 'public void create'
# Expected: first instructions are NEW + INVOKESPECIAL for the obfuscated wrapper class

# Confirm asset magic is project-specific (first 4 bytes differ from other projects):
xxd assets/yourasset.png | head -1
# The first 4 bytes are SHA-256(masterKey)[0:4] — unique to your key
```

---

## Limitations & security notes

- **String encryption** uses XOR — an obfuscation technique, not cryptographic. Per-string salting means each string requires individual analysis, but a determined reverse engineer can still recover strings given enough effort. Combine with ProGuard/R8 for release builds.
- **Asset encryption** uses AES-128-CTR — computationally secure. Known-plaintext attack (e.g. from PNG magic bytes) does not recover the key. Per-file derived keys mean breaking one file's keystream does not expose others.
- The AES key is embedded in the injected wrapper class as four arithmetic-veiled Int fields. It can be recovered by setting a breakpoint on the wrapper's `<clinit>` or by memory scanning at runtime. For stronger protection, derive one key factor from JNI native code.
- Does **not** protect against a live debugger (JDWP). Combine with ProGuard/R8, root detection, or debugger detection for release builds.
- `const val` string fields and annotation values may not be transformed (they can live in the constant pool differently). Verify with `javap -c` on your release build.
- Some frameworks rely on specific string constants for reflection or service lookup. Use `excludePackages` to skip those packages.

---

## License

MIT
