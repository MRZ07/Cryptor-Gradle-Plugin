# Cryptor-Gradle-Plugin

[![](https://jitpack.io/v/MRZ07/Cryptor-Gradle-Plugin.svg)](https://jitpack.io/#MRZ07/Cryptor-Gradle-Plugin)

A Gradle plugin that **encrypts all string literals and game assets at build time** using ASM bytecode transformation.
Strings are decrypted transparently at runtime — fully offline, with zero source-code changes required.

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

```
Your source (.kt / .java)
        │
        ▼  compileKotlin / compileJava
   .class files  ←── only your own sources; libraries are never touched
        │
        ▼  encryptStrings task
        │
        │  1. Visit every LDC String instruction via ASM
        │  2. XOR-encrypt the string with your 64-bit key
        │  3. Replace the instruction with:
        │       INVOKESTATIC <obfClass>.<obfMethod>(String)
        │  4. Inject the key-patched decryptor class (obfuscated name)
        │
        ▼
   .class files  — no plaintext strings, decryptor class named after your key
        │
        ▼  jar / dex / package as usual
```

The injected decryptor is **never named `StringDecryptor`** in the output.
Both the class name and method name are derived deterministically from your encryption key
(e.g. `ieuufi.ro(String)`), so every project gets unique names.
Each string is decrypted once on first use and cached — zero overhead on repeated access.

---

## Features

- Zero source-code changes required
- Encrypts all Kotlin **and** Java compiled classes
- Runtime decryptor auto-injected with a **key-derived obfuscated name** — `StringDecryptor.decrypt` never appears in decompiled output
- Debug builds skipped by default so stack traces stay readable during development
- Configurable 64-bit XOR key per project
- Package exclusion list — Kotlin stdlib, JDK, and Android framework always excluded automatically
- **ProGuard/R8 compatible** — no keep-rule needed; ProGuard further renames the already-obfuscated decryptor
- **Asset encryption (v1.1+)** — XOR-encrypts game assets at build time including **audio** (mp3, ogg, wav); `CryptorFilesWrapper` is auto-injected into the JAR and transparently decrypts files at runtime
- **Magic-header guard** — assets without the `C0DEBABE` header (audio, etc.) pass through unmodified, preventing corruption
- **ProGuard-safe activation (v1.2+)** — `CryptorFilesWrapper` is wired into `Gdx.files` via direct ASM bytecode injection into `create()`, not reflection; ProGuard renames both sides consistently

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
    id 'com.github.MRZ07.Cryptor-Gradle-Plugin' version 'v1.7.6'
}

cryptor {
    key = 0xDEADBEEFCAFEBABEL   // your 64-bit XOR key — change this!
    skipDebug = true             // skip encryption on debug builds
}
```

```kotlin
// build.gradle.kts (Kotlin DSL)
plugins {
    kotlin("jvm") version "2.0.0"   // or id("java")
    id("com.github.MRZ07.Cryptor-Gradle-Plugin") version "v1.7.6"

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
1. XOR-encrypt all supported asset files at build time and include them in the fat JAR
2. Inject `CryptorFilesWrapper` into the JAR — a `Files` proxy that decrypts on-the-fly
3. ASM-patch the `Game.create()` method to assign `Gdx.files = new CryptorFilesWrapper(Gdx.files)` — **no manual change to your `create()` needed** (v1.2+)

```groovy
// lwjgl3/build.gradle
plugins {
    id 'com.github.MRZ07.Cryptor-Gradle-Plugin' version 'v1.7.6'
}

def localProps = new Properties()
file("../local.properties").withInputStream { localProps.load(it) }

cryptor {
    enabled = true
    key = Long.parseUnsignedLong(localProps['encryptor.key'], 16)
    skipDebug = true
    encryptAssets = true
    assetsDir = file('../assets')      // path to your game assets folder
    // assetExtensions = ['tmx', 'png', 'jpg', 'jpeg', 'atlas', 'pack', 'json', 'fnt', 'properties', 'mp3', 'ogg', 'wav']
}
```

The plugin detects a plain JVM module and wires the encrypted classes and assets into the `jar` task automatically.

## Optional: Android module

```groovy
// android/build.gradle
plugins {
    id 'com.github.MRZ07.Cryptor-Gradle-Plugin' version 'v1.7.6'
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
> If asset encryption on iOS is required, the raw assets must be pre-encrypted out-of-band before the RoboVM build picks them up.

---

## Configuration Reference

All options go inside the `cryptor { }` block:

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `enabled` | `Boolean` | `true` | Master switch. Set to `false` to disable all encryption without removing the plugin block. Useful for plain vs obfuscated build comparisons. |
| `key` | `Long` | `0xDEADBEEFCAFEBABE` | 64-bit XOR key. **Always override this.** Determines the obfuscated decryptor class/method name. |
| `excludePackages` | `List<String>` | `[]` | Additional slash-separated package prefixes to skip (e.g. `['com/google/']`). Kotlin, JDK, and Android are always excluded. |
| `skipDebug` | `Boolean` | `true` | When `true`, debug build variants are not encrypted so stack traces remain readable during development. |
| `encryptStrings` | `Boolean` | `true` | When `true`, string literals in class files are XOR-encrypted. Set to `false` to keep readable strings while still encrypting assets. |
| `encryptAssets` | `Boolean` | `true` | When `true`, asset files in `assetsDir` are XOR-encrypted at build time and `CryptorFilesWrapper` is injected. Requires `assetsDir`. |
| `assetsDir` | `DirectoryProperty` | _(unset)_ | Path to the assets directory to encrypt. Must be set when `encryptAssets = true`. |
| `assetExtensions` | `List<String>` | see below | File extensions to encrypt. Default: `tmx, png, jpg, jpeg, atlas, pack, json, fnt, ttf, properties, mp3, ogg, wav`. |

---

## Available versions

> **[https://jitpack.io/#MRZ07/Cryptor-Gradle-Plugin](https://jitpack.io/#MRZ07/Cryptor-Gradle-Plugin)**

| Version | Status | Highlights |
|---------|--------|------------|
| `v1.0` | ✅ stable | String encryption, decryptor injection, ProGuard-safe obfuscated names |
| `v1.1` | ✅ stable | Asset encryption (`encryptAssets`), `CryptorFilesWrapper`, magic-header guard |
| `v1.2` | ✅ stable | ProGuard-safe activation — ASM patches `create()` directly; no reflection in user code |
| `v1.3` | ✅ stable | IDE-compatible asset encryption — raw assets on classpath, encrypted only in JAR |
| `v1.4` | ✅ stable | DSL renamed `cryptor {}`, audio encryption (mp3/ogg/wav), `enabled` master switch |
| `v1.5` | ✅ stable | `encryptStrings` flag, TTF font encryption |
| `v1.6.0` | ✅ stable | `CryptorAudioWrapper` — audio assets decrypted via temp file; full ProGuard/R8 compatibility on Android |
| `v1.6.1` | ✅ stable | `applyAndroid()` sets `encryptStrings` and `injectFilesWrapper` automatically |
| `v1.7.4` | ✅ stable | Android asset encryption; Gradle 9 compatibility; `CryptorFileHandle.map()` override |
| `v1.7.6` | ✅ stable | Improved Android asset encryption ordering; use this version |

---

## Internals

## Plugin source layout

```
src/main/kotlin/
├── CryptorPlugin.kt             # entry point — wires tasks, derives obfuscated names from key
├── CryptorExtension.kt          # DSL: enabled, key, excludePackages, skipDebug, encryptStrings, encryptAssets, assetsDir
├── EncryptClassesTask.kt        # ASM transformation + decryptor/wrapper injection + create() patch
├── EncryptAssetsTask.kt         # XOR-encrypts asset files, prepends C0DEBABE magic header
├── CryptorFilesWrapper.kt       # Runtime Files proxy — injected into JAR, decrypts on read
├── CryptorAudioWrapper.kt       # Runtime Audio proxy — decrypts audio assets to a temp file before passing to AndroidAudio; full ProGuard/R8 support
├── XorEncryptor.kt              # encrypt(String, Long): ByteArray
└── StringDecryptor.kt           # decryptor template — injected and renamed at build time
```

### Asset encryption pipeline (v1.1+)

```
assets/  (raw)
    │
    ▼  encryptAssets task
    │  1. For each file with a supported extension:
    │     a. XOR-encrypt with the 64-bit key
    │     b. Prepend 4-byte magic header: C0 DE BA BE
    │  2. Audio / unsupported files: copied as-is
    ▼
build/encryptedAssets/  → wired directly into the jar task (raw copies excluded)
                           Raw assets stay in resources.srcDirs for IDE/run task compatibility
```

### CryptorFilesWrapper activation (v1.2+)

After string encryption and wrapper injection, the plugin scans the output directory for the
class extending `com/badlogic/gdx/Game` and prepends bytecode instructions to both `create()V`
and `resume()V`:

```
// Gdx.files
NEW     CryptorFilesWrapper
DUP
GETSTATIC  com/badlogic/gdx/Gdx.files
INVOKESPECIAL  CryptorFilesWrapper.<init>(Lcom/badlogic/gdx/Files;)V
PUTSTATIC  com/badlogic/gdx/Gdx.files

// Gdx.audio (v1.6.0+)
NEW     CryptorAudioWrapper
DUP
GETSTATIC  com/badlogic/gdx/Gdx.audio
INVOKESPECIAL  CryptorAudioWrapper.<init>(Lcom/badlogic/gdx/Audio;)V
PUTSTATIC  com/badlogic/gdx/Gdx.audio
```

`CryptorAudioWrapper` intercepts `newSound()` / `newMusic()` calls and decrypts the asset to a
temp file before delegating to the platform audio backend, ensuring full compatibility with
ProGuard/R8 release builds on Android.

## Runtime decryptor

The decryptor is compiled into the plugin JAR as a template, then injected into your project's
class output with the key patched in and both class name and method name renamed via ASM `ClassRemapper`.
**Do not add it manually** — it is handled entirely by the plugin.

```kotlin
object StringDecryptor {         // renamed in output, e.g. → ieuufi
    private val KEY: Long = 0L   // patched at build time with your real key

    private val cache = HashMap<String, String>()

    @JvmStatic
    fun decrypt(encoded: String): String {   // renamed in output, e.g. → ro
        return cache.getOrPut(encoded) {
            val data = encoded.toByteArray(Charsets.ISO_8859_1)
            val key = KEY
            String(ByteArray(data.size) { i ->
                (data[i].toInt() xor ((key shr ((i % 8) * 8)) and 0xFF).toInt()).toByte()
            })
        }
    }
}
```

The obfuscated name is **deterministic**: same key → same names across every build, keeping
Gradle's incremental build cache valid.

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
# Expected output: something like  ieuufi.ro:(Ljava/lang/String;)Ljava/lang/String;

# Confirm CryptorFilesWrapper activation is patched into create() (not reflection):
javap -c MyGame.class | grep -A 10 'public void create'
# Expected: first instruction is  new  CryptorFilesWrapper  (not  invokestatic Class.forName)

# Confirm the constant pool entry is a Class reference (not a String):
javap -verbose MyGame.class | grep -A 2 'CryptorFilesWrapper'
# Expected:  #N = Class  #M  // CryptorFilesWrapper

# Confirm asset files have the magic header (encrypted:
xxd assets/yourasset.png | head -1
# Expected first bytes:  c0 de ba be  ...
```

---

## Limitations & security notes

- XOR is an **obfuscation** technique, not cryptographic encryption. A determined reverse engineer can recover strings — this raises the bar, it is not a hard wall.
- The decryption key is embedded in the injected decryptor class. For stronger protection, split the key and store one half in JNI native code.
- Does **not** protect against a live debugger (JDWP). Combine with ProGuard/R8 for release builds.
- `const val` string fields and annotation values may not be transformed (they can live in the constant pool differently). Verify with `javap -c` on your release build.
- Some frameworks rely on specific string constants for reflection or service lookup. Use `excludePackages` to skip those packages.

---

## License

MIT


