# AES Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace XOR asset encryption with AES-128-CTR + per-file derived keys and split the runtime key across 4 int fields instead of one Long, making reverse engineering significantly harder.

**Architecture:** A new `AesFileEncryptor` utility object handles all AES logic (key derivation, per-file key, encryption/decryption). `EncryptAssetsTask` delegates to it. `CryptorFilesWrapper` replaces its single `KEY: Long` with four `KEY_0..KEY_3: Int` fields and uses `AesFileEncryptor` for decryption. The ASM patcher in `EncryptClassesTask` derives the 16-byte AES key from the user's `Long` via SHA-256 then patches the four int fields. String encryption stays XOR (fast, short strings, unaffected by known-plaintext concern).

**Tech Stack:** Kotlin, ASM 9, `javax.crypto` (JDK built-in, no new deps), `java.security.MessageDigest` for SHA-256, `java.security.SecureRandom` for IVs.

## Global Constraints

- No new external dependencies — only JDK crypto (`javax.crypto`, `java.security`)
- Public API surface of `CryptorExtension` unchanged — `key: Property<Long>` stays
- `build.gradle.kts` version bumped to `v1.8.0`
- Magic header bytes change from `C0 DE BA BE` (XOR) → `C0 DE CA FE` (AES) — clean break, forces rebuild
- New encrypted header layout: `[4 magic][16 IV][N ciphertext]` = 20-byte overhead per file
- String encryption (`XorEncryptor` / `StringDecryptor`) is **not changed** — XOR stays for strings
- All changes in `Cryptor-Gradle-Plugin` repo only; game repos updated separately after release

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `src/main/kotlin/AesFileEncryptor.kt` | **Create** | All AES crypto: key derivation, per-file key, encrypt, decrypt, magic constant |
| `src/main/kotlin/CryptorFilesWrapper.kt` | **Modify** | Replace `KEY: Long` with `KEY_0..KEY_3: Int`; delegate decrypt to `AesFileEncryptor` |
| `src/main/kotlin/EncryptAssetsTask.kt` | **Modify** | Use `AesFileEncryptor` instead of `XorEncryptor`; pass relative path for per-file key |
| `src/main/kotlin/EncryptClassesTask.kt` | **Modify** | `patchCryptorFilesWrapperKeys`: patch 4 int fields instead of 1 long |
| `src/main/kotlin/CryptorPlugin.kt` | **Modify** | Android inline encryption block: use `AesFileEncryptor` |
| `build.gradle.kts` | **Modify** | Bump `version` to `v1.8.0` |
| `XorEncryptor.kt` | **No change** | String encryption stays XOR |

---

## Task 1: Create `AesFileEncryptor.kt`

**Files:**
- Create: `src/main/kotlin/AesFileEncryptor.kt`

**Interfaces:**
- Produces:
  - `AesFileEncryptor.MAGIC: ByteArray` — `[C0, DE, CA, FE]`
  - `AesFileEncryptor.HEADER_SIZE: Int` — `20`
  - `AesFileEncryptor.deriveAesKey(longKey: Long): ByteArray` — SHA-256 of key bytes, first 16
  - `AesFileEncryptor.deriveFileKey(masterKey: ByteArray, relativePath: String): ByteArray` — SHA-256(masterKey ∥ normalizedPath), first 16
  - `AesFileEncryptor.encrypt(data: ByteArray, masterKey: ByteArray, relativePath: String): ByteArray` — returns MAGIC + random IV + AES-CTR ciphertext
  - `AesFileEncryptor.decrypt(raw: ByteArray, masterKey: ByteArray, relativePath: String): ByteArray` — strips header, AES-CTR decrypts; returns raw unchanged if no magic
  - `AesFileEncryptor.hasMagic(raw: ByteArray): Boolean`

- [ ] **Step 1: Write the file**

```kotlin
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-128-CTR asset encryption with per-file derived keys.
 *
 * Security properties:
 *  - AES-128-CTR: known-plaintext does not recover the key (computationally infeasible)
 *  - Per-file derived key: recovering one file's key does not help with other files
 *  - Random 16-byte IV per file: identical assets produce different ciphertexts
 *
 * Header layout (20 bytes):
 *   [0..3]   magic  C0 DE CA FE
 *   [4..19]  random IV (16 bytes)
 *   [20..]   AES-128-CTR ciphertext
 */
object AesFileEncryptor {

    val MAGIC = byteArrayOf(0xC0.toByte(), 0xDE.toByte(), 0xCA.toByte(), 0xFE.toByte())
    const val HEADER_SIZE = 20  // 4 magic + 16 IV

    // -------------------------------------------------------------------------
    // Key derivation
    // -------------------------------------------------------------------------

    /**
     * Derives a 16-byte AES-128 master key from the user-supplied 64-bit config key.
     * Uses SHA-256 so the 64-bit input is properly expanded; first 16 bytes of digest.
     */
    fun deriveAesKey(longKey: Long): ByteArray {
        val keyBytes = ByteBuffer.allocate(8).putLong(longKey).array()
        return sha256(keyBytes).copyOf(16)
    }

    /**
     * Derives a file-specific 16-byte key: SHA-256(masterKey ∥ normalizedPath)[0:16].
     * Recovering one file's keystream does not expose the master key or other files.
     */
    fun deriveFileKey(masterKey: ByteArray, relativePath: String): ByteArray {
        val normalized = relativePath.lowercase().replace('\\', '/')
        val md = MessageDigest.getInstance("SHA-256")
        md.update(masterKey)
        md.update(normalized.toByteArray(Charsets.UTF_8))
        return md.digest().copyOf(16)
    }

    // -------------------------------------------------------------------------
    // Encrypt / Decrypt
    // -------------------------------------------------------------------------

    /**
     * Encrypts [data] for the asset at [relativePath].
     * Output: MAGIC (4) + random IV (16) + AES-128-CTR ciphertext (N).
     */
    fun encrypt(data: ByteArray, masterKey: ByteArray, relativePath: String): ByteArray {
        val fileKey = deriveFileKey(masterKey, relativePath)
        val iv = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val ciphertext = aesCtr(data, fileKey, iv, Cipher.ENCRYPT_MODE)
        return MAGIC + iv + ciphertext
    }

    /**
     * Decrypts [raw] if it starts with [MAGIC]; otherwise returns [raw] unchanged.
     * [relativePath] must match the path used at encryption time.
     */
    fun decrypt(raw: ByteArray, masterKey: ByteArray, relativePath: String): ByteArray {
        if (!hasMagic(raw)) return raw
        val iv = raw.copyOfRange(4, 20)
        val ciphertext = raw.copyOfRange(20, raw.size)
        val fileKey = deriveFileKey(masterKey, relativePath)
        return aesCtr(ciphertext, fileKey, iv, Cipher.DECRYPT_MODE)
    }

    fun hasMagic(raw: ByteArray): Boolean =
        raw.size >= HEADER_SIZE &&
        raw[0] == MAGIC[0] && raw[1] == MAGIC[1] &&
        raw[2] == MAGIC[2] && raw[3] == MAGIC[3]

    // -------------------------------------------------------------------------
    // Key reconstruction from four split Int fields (used at runtime)
    // -------------------------------------------------------------------------

    /**
     * Reconstructs the 16-byte master key from the four Int fields patched by ASM.
     * Layout: KEY_0 = bytes 0-3 (most significant), KEY_3 = bytes 12-15 (least significant).
     */
    fun masterKeyFromInts(k0: Int, k1: Int, k2: Int, k3: Int): ByteArray {
        val buf = ByteBuffer.allocate(16)
        buf.putInt(k0); buf.putInt(k1); buf.putInt(k2); buf.putInt(k3)
        return buf.array()
    }

    /**
     * Splits a 16-byte key into four Ints (for ASM patching).
     */
    fun splitKey(keyBytes: ByteArray): IntArray {
        require(keyBytes.size == 16) { "Key must be 16 bytes" }
        val buf = ByteBuffer.wrap(keyBytes)
        return intArrayOf(buf.getInt(), buf.getInt(), buf.getInt(), buf.getInt())
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    private fun aesCtr(data: ByteArray, key: ByteArray, iv: ByteArray, mode: Int): ByteArray {
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(mode, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(data)
    }
}
```

- [ ] **Step 2: Verify it compiles**

```bash
cd /Users/RASHEEM/Desktop/Repos/MRZ07/Cryptor-Gradle-Plugin
./gradlew compileKotlin 2>&1 | tail -20
```
Expected: `BUILD SUCCESSFUL`

- [ ] **Step 3: Commit**

```bash
git add src/main/kotlin/AesFileEncryptor.kt
git commit -m "feat: add AesFileEncryptor — AES-128-CTR with per-file derived keys"
```

---

## Task 2: Update `CryptorFilesWrapper.kt`

**Files:**
- Modify: `src/main/kotlin/CryptorFilesWrapper.kt`

**Interfaces:**
- Consumes: `AesFileEncryptor.masterKeyFromInts`, `AesFileEncryptor.decrypt`, `AesFileEncryptor.HEADER_SIZE`, `AesFileEncryptor.hasMagic`
- Produces: `KEY_0: Int`, `KEY_1: Int`, `KEY_2: Int`, `KEY_3: Int` (patched by ASM at build time); `ENABLED: Boolean`

- [ ] **Step 1: Replace the file contents**

```kotlin
import com.badlogic.gdx.Files
import com.badlogic.gdx.files.FileHandle
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.InputStreamReader
import java.io.Reader

/**
 * Wraps [Files] so every [FileHandle] returned for internal files is transparently decrypted.
 *
 * Security improvements over the XOR version:
 *  - AES-128-CTR encryption: known-plaintext does not recover the key
 *  - Per-file derived keys: one broken file does not expose other files
 *  - Random IV per file: identical assets produce different ciphertexts
 *  - Master key split across KEY_0..KEY_3 (four Ints): harder to locate
 *    in bytecode/memory than a single Long constant
 *
 * KEY_0..KEY_3 and ENABLED are patched to their real values by the
 * Cryptor Gradle Plugin at build time via ASM <clinit> prepend.
 * At compile time they remain 0 / false so dev builds are unaffected.
 */
class CryptorFilesWrapper(private val delegate: Files) : Files by delegate {

    companion object {
        // 16-byte AES master key split into four Ints.
        // Layout: KEY_0 = bytes 0-3 (MSB), KEY_3 = bytes 12-15 (LSB).
        // All four are patched atomically in <clinit> by EncryptClassesTask.
        @JvmField var KEY_0: Int = 0
        @JvmField var KEY_1: Int = 0
        @JvmField var KEY_2: Int = 0
        @JvmField var KEY_3: Int = 0
        @JvmField var ENABLED: Boolean = false

        private fun masterKey(): ByteArray =
            AesFileEncryptor.masterKeyFromInts(KEY_0, KEY_1, KEY_2, KEY_3)
    }

    override fun internal(path: String): FileHandle =
        if (ENABLED) CryptorFileHandle(delegate.internal(path)) else delegate.internal(path)

    // -------------------------------------------------------------------------
    // Inner FileHandle that AES-decrypts on read
    // -------------------------------------------------------------------------

    inner class CryptorFileHandle(private val source: FileHandle)
        : FileHandle(source.path(), source.type()) {

        private fun maybeDecrypt(raw: ByteArray): ByteArray =
            if (AesFileEncryptor.hasMagic(raw))
                AesFileEncryptor.decrypt(raw, masterKey(), normPath())
            else raw

        /** Normalized relative path — must match the path used at encryption time. */
        private fun normPath(): String = source.path().replace('\\', '/')

        override fun read(): InputStream = ByteArrayInputStream(maybeDecrypt(source.readBytes()))
        override fun readBytes(): ByteArray = maybeDecrypt(source.readBytes())
        override fun reader(): Reader = InputStreamReader(read(), Charsets.UTF_8)
        override fun reader(charset: String): Reader = InputStreamReader(read(), charset)

        override fun map(): java.nio.ByteBuffer {
            val data = readBytes()
            val buf = java.nio.ByteBuffer.allocateDirect(data.size)
            buf.put(data)
            buf.flip()
            return buf
        }

        override fun path(): String = source.path()
        override fun name(): String = source.name()
        override fun extension(): String = source.extension()
        override fun nameWithoutExtension(): String = source.nameWithoutExtension()
        override fun pathWithoutExtension(): String = source.pathWithoutExtension()
        override fun type(): Files.FileType = source.type()
        override fun exists(): Boolean = source.exists()
        override fun length(): Long {
            val raw = source.readBytes()
            return if (AesFileEncryptor.hasMagic(raw))
                (raw.size - AesFileEncryptor.HEADER_SIZE).toLong()
            else raw.size.toLong()
        }
        override fun lastModified(): Long = source.lastModified()
        override fun isDirectory(): Boolean = source.isDirectory

        override fun child(name: String): FileHandle = CryptorFileHandle(source.child(name))
        override fun sibling(name: String): FileHandle = CryptorFileHandle(source.sibling(name))
        override fun parent(): FileHandle = CryptorFileHandle(source.parent())

        override fun list(): Array<FileHandle> = source.list().map { CryptorFileHandle(it) }.toTypedArray()
        override fun list(suffix: String): Array<FileHandle> = source.list(suffix).map { CryptorFileHandle(it) }.toTypedArray()
        override fun file(): java.io.File = source.file()
    }
}
```

- [ ] **Step 2: Compile**

```bash
./gradlew compileKotlin 2>&1 | tail -20
```
Expected: `BUILD SUCCESSFUL`

- [ ] **Step 3: Commit**

```bash
git add src/main/kotlin/CryptorFilesWrapper.kt
git commit -m "feat: CryptorFilesWrapper — AES-128-CTR decrypt, split KEY_0..KEY_3"
```

---

## Task 3: Update `EncryptAssetsTask.kt`

**Files:**
- Modify: `src/main/kotlin/EncryptAssetsTask.kt`

**Interfaces:**
- Consumes: `AesFileEncryptor.deriveAesKey`, `AesFileEncryptor.encrypt`, `AesFileEncryptor.hasMagic`

- [ ] **Step 1: Replace the file contents**

```kotlin
import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.*
import java.io.File

@CacheableTask
abstract class EncryptAssetsTask : DefaultTask() {

    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val inputDir: DirectoryProperty

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @get:Input
    abstract val encryptionKey: Property<Long>

    @get:Input
    abstract val assetExtensions: ListProperty<String>

    @TaskAction
    fun encrypt() {
        val input  = inputDir.get().asFile
        val output = outputDir.get().asFile
        val exts   = assetExtensions.get().map { it.lowercase() }.toSet()

        // Derive the 16-byte AES master key from the user-supplied 64-bit key
        val masterKey = AesFileEncryptor.deriveAesKey(encryptionKey.get())

        output.deleteRecursively()
        output.mkdirs()

        input.walkTopDown().filter { it.isFile }.forEach { src ->
            val relative = src.relativeTo(input)
            val dest = File(output, relative.path)
            dest.parentFile.mkdirs()

            if (src.extension.lowercase() in exts) {
                val raw = src.readBytes()
                // Skip already-encrypted files (idempotent)
                if (AesFileEncryptor.hasMagic(raw)) {
                    dest.writeBytes(raw)
                } else {
                    // Use forward-slash relative path — matches CryptorFilesWrapper.normPath()
                    val relPath = relative.path.replace(File.separatorChar, '/')
                    dest.writeBytes(AesFileEncryptor.encrypt(raw, masterKey, relPath))
                }
            } else {
                src.copyTo(dest, overwrite = true)
            }
        }
    }
}
```

- [ ] **Step 2: Compile**

```bash
./gradlew compileKotlin 2>&1 | tail -20
```
Expected: `BUILD SUCCESSFUL`

- [ ] **Step 3: Commit**

```bash
git add src/main/kotlin/EncryptAssetsTask.kt
git commit -m "feat: EncryptAssetsTask — AES-128-CTR with per-file derived keys"
```

---

## Task 4: Update `EncryptClassesTask.kt` — ASM key patcher

**Files:**
- Modify: `src/main/kotlin/EncryptClassesTask.kt` (only `patchCryptorFilesWrapperKeys`)

- [ ] **Step 1: Replace `patchCryptorFilesWrapperKeys`**

Find and replace the existing `patchCryptorFilesWrapperKeys` method (currently lines ~356–382):

OLD:
```kotlin
    private fun patchCryptorFilesWrapperKeys(bytes: ByteArray, key: Long): ByteArray {
        val reader = ClassReader(bytes)
        val writer = ClassWriter(reader, ClassWriter.COMPUTE_MAXS)

        reader.accept(object : ClassVisitor(ASM9, writer) {
            override fun visitMethod(
                access: Int, name: String, descriptor: String,
                signature: String?, exceptions: Array<out String>?
            ): MethodVisitor {
                val mv = super.visitMethod(access, name, descriptor, signature, exceptions)
                if (name == "<clinit>") {
                    return object : MethodVisitor(ASM9, mv) {
                        override fun visitCode() {
                            super.visitCode()
                            mv.visitLdcInsn(key)
                            mv.visitFieldInsn(PUTSTATIC, "CryptorFilesWrapper", "KEY", "J")
                            mv.visitInsn(ICONST_1)
                            mv.visitFieldInsn(PUTSTATIC, "CryptorFilesWrapper", "ENABLED", "Z")
                        }
                    }
                }
                return mv
            }
        }, 0)

        return writer.toByteArray()
    }
```

NEW:
```kotlin
    /**
     * Derives the 16-byte AES key from [key], splits it into four Ints, then
     * prepends KEY_0..KEY_3 = <values>; ENABLED = true to CryptorFilesWrapper's <clinit>.
     *
     * Four separate Int PUTSTATICs are harder to recognise as "the key" than a single
     * LDC Long instruction — each looks like an unrelated integer constant.
     */
    private fun patchCryptorFilesWrapperKeys(bytes: ByteArray, key: Long): ByteArray {
        val reader = ClassReader(bytes)
        val writer = ClassWriter(reader, ClassWriter.COMPUTE_MAXS)

        val masterKey = AesFileEncryptor.deriveAesKey(key)
        val parts = AesFileEncryptor.splitKey(masterKey)  // [k0, k1, k2, k3]

        reader.accept(object : ClassVisitor(ASM9, writer) {
            override fun visitMethod(
                access: Int, name: String, descriptor: String,
                signature: String?, exceptions: Array<out String>?
            ): MethodVisitor {
                val mv = super.visitMethod(access, name, descriptor, signature, exceptions)
                if (name == "<clinit>") {
                    return object : MethodVisitor(ASM9, mv) {
                        override fun visitCode() {
                            super.visitCode()
                            // Patch four Int fields — split key, harder to spot statically
                            for (i in 0..3) {
                                mv.visitLdcInsn(parts[i])
                                mv.visitFieldInsn(PUTSTATIC, "CryptorFilesWrapper", "KEY_$i", "I")
                            }
                            mv.visitInsn(ICONST_1)
                            mv.visitFieldInsn(PUTSTATIC, "CryptorFilesWrapper", "ENABLED", "Z")
                        }
                    }
                }
                return mv
            }
        }, 0)

        return writer.toByteArray()
    }
```

- [ ] **Step 2: Compile**

```bash
./gradlew compileKotlin 2>&1 | tail -20
```
Expected: `BUILD SUCCESSFUL`

- [ ] **Step 3: Commit**

```bash
git add src/main/kotlin/EncryptClassesTask.kt
git commit -m "feat: EncryptClassesTask — patch KEY_0..KEY_3 Int fields via ASM"
```

---

## Task 5: Update Android inline encryption in `CryptorPlugin.kt`

**Files:**
- Modify: `src/main/kotlin/CryptorPlugin.kt` (Android `doLast` block only)

- [ ] **Step 1: Replace the Android inline encryption block**

Find the `doLast` block inside `applyAndroid` (currently ~lines 140–153):

OLD:
```kotlin
                    t.doLast {
                        val dir = mergedDir.get().asFile
                        if (!dir.exists()) return@doLast
                        val key  = extension.key.get()
                        val exts = extension.assetExtensions.get().map { it.lowercase() }.toSet()
                        val magic = byteArrayOf(0xC0.toByte(), 0xDE.toByte(), 0xBA.toByte(), 0xBE.toByte())
                        dir.walkTopDown().filter { it.isFile }.forEach { src ->
                            if (src.extension.lowercase() !in exts) return@forEach
                            val raw = src.readBytes()
                            if (raw.size >= 4 && raw[0] == magic[0] && raw[1] == magic[1] &&
                                raw[2] == magic[2] && raw[3] == magic[3]) return@forEach
                            src.writeBytes(magic + XorEncryptor.encrypt(raw, key))
                        }
                    }
```

NEW:
```kotlin
                    t.doLast {
                        val dir = mergedDir.get().asFile
                        if (!dir.exists()) return@doLast
                        val masterKey = AesFileEncryptor.deriveAesKey(extension.key.get())
                        val exts = extension.assetExtensions.get().map { it.lowercase() }.toSet()
                        dir.walkTopDown().filter { it.isFile }.forEach { src ->
                            if (src.extension.lowercase() !in exts) return@forEach
                            val raw = src.readBytes()
                            if (AesFileEncryptor.hasMagic(raw)) return@forEach
                            val relPath = src.relativeTo(dir).path.replace(java.io.File.separatorChar, '/')
                            src.writeBytes(AesFileEncryptor.encrypt(raw, masterKey, relPath))
                        }
                    }
```

- [ ] **Step 2: Compile**

```bash
./gradlew compileKotlin 2>&1 | tail -20
```
Expected: `BUILD SUCCESSFUL`

- [ ] **Step 3: Commit**

```bash
git add src/main/kotlin/CryptorPlugin.kt
git commit -m "feat: Android path — AES-128-CTR asset encryption via AesFileEncryptor"
```

---

## Task 6: Bump version, full build, tag release

**Files:**
- Modify: `build.gradle.kts`

- [ ] **Step 1: Update version**

Change line 8 from:
```kotlin
version = "v1.7.8"
```
To:
```kotlin
version = "v1.8.0"
```

- [ ] **Step 2: Full build**

```bash
./gradlew build 2>&1 | tail -30
```
Expected: `BUILD SUCCESSFUL`

- [ ] **Step 3: Commit and tag**

```bash
git add build.gradle.kts
git commit -m "chore: release v1.8.0 — AES-128-CTR + per-file keys + split key fields"
git tag v1.8.0
```

---

## Task 7: Update all game repos to v1.8.0

All four game repos reference `version "v1.7.8"` in their `lwjgl3/build.gradle`. Update each to `v1.8.0`.

**Files:**
- Modify: `SamsWorld/lwjgl3/build.gradle`
- Modify: `ZacksWorld/lwjgl3/build.gradle`
- Modify: `SamsLevelMaker/lwjgl3/build.gradle`
- Modify: `ZacksLevelMaker/lwjgl3/build.gradle`

- [ ] **Step 1: Sed-replace version in all four**

```bash
sed -i '' 's/Cryptor-Gradle-Plugin") version "v1.7.8"/Cryptor-Gradle-Plugin") version "v1.8.0"/' \
  /Users/RASHEEM/Desktop/Repos/MRZ07/SamsWorld/lwjgl3/build.gradle \
  /Users/RASHEEM/Desktop/Repos/MRZ07/ZacksWorld/lwjgl3/build.gradle \
  /Users/RASHEEM/Desktop/Repos/MRZ07/SamsLevelMaker/lwjgl3/build.gradle \
  /Users/RASHEEM/Desktop/Repos/MRZ07/ZacksLevelMaker/lwjgl3/build.gradle
```

- [ ] **Step 2: Also update Android build.gradle files if present**

```bash
for repo in SamsWorld ZacksWorld SamsLevelMaker ZacksLevelMaker; do
  find /Users/RASHEEM/Desktop/Repos/MRZ07/$repo/android -name "build.gradle" -exec \
    grep -l "Cryptor-Gradle-Plugin" {} \; | xargs -I{} \
    sed -i '' 's/Cryptor-Gradle-Plugin.*v1\.7\.8/Cryptor-Gradle-Plugin") version "v1.8.0"/' {}
done
```

- [ ] **Step 3: Verify all four updated**

```bash
grep -r "Cryptor-Gradle-Plugin" \
  /Users/RASHEEM/Desktop/Repos/MRZ07/SamsWorld/lwjgl3/build.gradle \
  /Users/RASHEEM/Desktop/Repos/MRZ07/ZacksWorld/lwjgl3/build.gradle \
  /Users/RASHEEM/Desktop/Repos/MRZ07/SamsLevelMaker/lwjgl3/build.gradle \
  /Users/RASHEEM/Desktop/Repos/MRZ07/ZacksLevelMaker/lwjgl3/build.gradle
```
Expected: all four show `v1.8.0`

- [ ] **Step 4: Commit each repo**

```bash
cd /Users/RASHEEM/Desktop/Repos/MRZ07/SamsWorld
git add lwjgl3/build.gradle && git commit -m "chore: upgrade Cryptor-Gradle-Plugin to v1.8.0"

cd /Users/RASHEEM/Desktop/Repos/MRZ07/ZacksWorld
git add lwjgl3/build.gradle && git commit -m "chore: upgrade Cryptor-Gradle-Plugin to v1.8.0"

cd /Users/RASHEEM/Desktop/Repos/MRZ07/SamsLevelMaker
git add lwjgl3/build.gradle && git commit -m "chore: upgrade Cryptor-Gradle-Plugin to v1.8.0"

cd /Users/RASHEEM/Desktop/Repos/MRZ07/ZacksLevelMaker
git add lwjgl3/build.gradle && git commit -m "chore: upgrade Cryptor-Gradle-Plugin to v1.8.0"
```
