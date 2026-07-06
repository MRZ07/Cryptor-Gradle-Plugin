import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.*
import org.objectweb.asm.*
import org.objectweb.asm.Opcodes.*
import org.objectweb.asm.commons.ClassRemapper
import org.objectweb.asm.commons.Remapper
import java.io.File

/**
 * Gradle task that:
 *  1. Walks all .class files under [inputDirs] (and optionally [inputDir]).
 *  2. Replaces every LDC string instruction with an INVOKESTATIC to the injected decryptor.
 *  3. Copies inputs → [outputDir] (or transforms in-place on JVM tasks).
 *  4. Injects the decryptor class (with the real key patched in) using the obfuscated
 *     [decryptorClassName] / [decryptorMethodName] so the runtime class is never named
 *     "StringDecryptor" and the method is never called "decrypt" in the output bytecode.
 */
@CacheableTask
abstract class EncryptClassesTask : DefaultTask() {

    /**
     * Multiple compile-output directories to encrypt (e.g. Kotlin + Java classes).
     * Used by the JVM wiring path.
     */
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val inputDirs: ConfigurableFileCollection

    /**
     * Single directory variant kept for backward compatibility with the Android wiring path.
     * If set, its contents are merged into the processing alongside [inputDirs].
     */
    @get:Optional
    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val inputDir: DirectoryProperty

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @get:Input
    abstract val encryptionKey: Property<Long>

    @get:Input
    abstract val excludePackages: ListProperty<String>

    /** Internal name (slash-separated) of the injected decryptor class, e.g. "ieuifi". */
    @get:Input
    abstract val decryptorClassName: Property<String>

    /** Method name of the decryption entry point, e.g. "ro". */
    @get:Input
    abstract val decryptorMethodName: Property<String>

    /**
     * When true (default), string LDC instructions in class files are replaced with
     * an INVOKESTATIC call to the injected decryptor. When false, class files are
     * copied as-is (but CryptorFilesWrapper is still injected if [injectFilesWrapper] is set).
     */
    @get:Input
    @get:Optional
    abstract val encryptStrings: Property<Boolean>

    /**
     * When true, CryptorFilesWrapper and its inner class are injected into the output
     * with KEY_0..KEY_3 patched to the real values.
     */
    @get:Input
    @get:Optional
    abstract val injectFilesWrapper: Property<Boolean>

    /**
     * Hash of the bundled StringDecryptor.class template (injected at runtime into the
     * target project). When this class changes (e.g. encryption algorithm update), the
     * hash changes, and Gradle invalidates the task's build-cache entry — preventing stale
     * cached output from being used with a mismatched encryption algorithm.
     */
    @get:Input
    @get:Optional
    abstract val runtimeDecryptorHash: Property<String>

    // -----------------------------------------------------------------------
    // Always-excluded internal prefixes
    // -----------------------------------------------------------------------
    private val builtinExclusions = listOf(
        "kotlin/",
        "kotlinx/",
        "java/",
        "javax/",
        "android/",
        "StringDecryptor"   // safety: exclude the template class name in case it appears in sources
    )

    @TaskAction
    fun transform() {
        val output        = outputDir.get().asFile
        val key           = encryptionKey.get()
        val extra         = excludePackages.get()
        val decryptClass  = decryptorClassName.get()
        val decryptMethod = decryptorMethodName.get()

        // Also exclude the dynamically-derived decryptor class by its obfuscated name
        val allExclusions = extra + decryptClass

        output.deleteRecursively()
        output.mkdirs()

        // Collect all source directories to process
        val sources = mutableListOf<File>()
        inputDirs.files.filter { it.isDirectory }.forEach { sources.add(it) }
        inputDir.orNull?.asFile?.takeIf { it.isDirectory && it !in sources }?.let { sources.add(it) }

        // Hoist constant: evaluated once per task run, not once per file in the parallel loop.
        val doEncrypt = encryptStrings.orElse(true).get()

        sources.forEach { inputRoot ->
            inputRoot.walkTopDown().filter { it.isFile }.toList()
                .parallelStream()
                .forEach { classFile ->
                    val relative = classFile.relativeTo(inputRoot)
                    val dest = File(output, relative.path)
                    if (dest.exists()) return@forEach
                    dest.parentFile?.mkdirs()

                    if (classFile.extension != "class") {
                        classFile.copyTo(dest)
                        return@forEach
                    }

                    val internalName = relative.path.removeSuffix(".class").replace(File.separatorChar, '/')
                    if (isExcluded(internalName, allExclusions)) {
                        classFile.copyTo(dest)
                        return@forEach
                    }

                    val bytes = if (doEncrypt)
                        transformClass(classFile.readBytes(), key, decryptClass, decryptMethod)
                    else
                        classFile.readBytes()
                    dest.writeBytes(bytes)
                }
        }

        if (encryptStrings.orElse(true).get()) {
            injectDecryptor(output, key, decryptClass, decryptMethod)
        }

        if (injectFilesWrapper.orElse(false).get()) {
            injectCryptorFilesWrapper(output, key)
            patchGdxFilesActivation(
                output,
                CryptorPlugin.deriveFilesWrapperName(key),
                CryptorPlugin.deriveAudioWrapperName(key)
            )
        }
    }

    // -----------------------------------------------------------------------
    // ASM transformation
    // -----------------------------------------------------------------------
    private fun transformClass(
        bytes: ByteArray, key: Long,
        decryptorClass: String, decryptorMethod: String
    ): ByteArray {
        val reader = ClassReader(bytes)
        val writer = ClassWriter(reader, ClassWriter.COMPUTE_MAXS)
        reader.accept(EncryptingClassVisitor(writer, key, decryptorClass, decryptorMethod), 0)
        return writer.toByteArray()
    }

    private class EncryptingClassVisitor(
        cv: ClassVisitor,
        private val key: Long,
        private val decryptorClass: String,
        private val decryptorMethod: String
    ) : ClassVisitor(ASM9, cv) {

        override fun visitMethod(
            access: Int, name: String, descriptor: String,
            signature: String?, exceptions: Array<out String>?
        ): MethodVisitor {
            val mv = super.visitMethod(access, name, descriptor, signature, exceptions)
            return EncryptingMethodVisitor(mv, key, decryptorClass, decryptorMethod)
        }
    }

    private class EncryptingMethodVisitor(
        mv: MethodVisitor,
        private val key: Long,
        private val decryptorClass: String,
        private val decryptorMethod: String
    ) : MethodVisitor(ASM9, mv) {

        override fun visitLdcInsn(value: Any?) {
            if (value !is String) {
                super.visitLdcInsn(value)
                return
            }

            // AES-128-CTR string encryption.
            // IV = first 8 bytes of murmur64(plaintext), repeated to 16 bytes.
            // Stored as ISO-8859-1 chars: [8-byte IV prefix][ciphertext].
            val plainBytes = value.toByteArray(Charsets.UTF_8)
            val ivLong     = XorEncryptor.murmur64(plainBytes)
            val ivPrefix   = ByteArray(8) { i -> ((ivLong ushr (i * 8)) and 0xFF).toByte() }
            val iv         = ivPrefix + ivPrefix              // pad to 16 bytes

            val masterKey  = AesFileEncryptor.deriveAesKey(key)
            val cipher     = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding")
            cipher.init(
                javax.crypto.Cipher.ENCRYPT_MODE,
                javax.crypto.spec.SecretKeySpec(masterKey, "AES"),
                javax.crypto.spec.IvParameterSpec(iv)
            )
            val cipherBytes    = cipher.doFinal(plainBytes)
            val encryptedString = String(ivPrefix + cipherBytes, Charsets.ISO_8859_1)

            mv.visitLdcInsn(encryptedString)
            mv.visitMethodInsn(
                INVOKESTATIC,
                decryptorClass,
                decryptorMethod,
                "(Ljava/lang/String;)Ljava/lang/String;",
                false
            )
        }
    }

    // -----------------------------------------------------------------------
    // Decryptor injection: patch the key, then rename class + method
    // -----------------------------------------------------------------------
    private fun injectDecryptor(
        outputDir: File, key: Long,
        decryptorClass: String, decryptorMethod: String
    ) {
        val resourcePath = "StringDecryptor.class"
        val templateBytes = EncryptClassesTask::class.java.classLoader
            .getResourceAsStream(resourcePath)
            ?.readBytes()
            ?: error("StringDecryptor.class template not found in plugin JAR resources")

        // Step 1: patch KEY into <clinit> (still uses "StringDecryptor" as owner)
        val patched = patchDecryptorKey(templateBytes, key)
        // Step 2: rename StringDecryptor → decryptorClass, decrypt → decryptorMethod
        //         ClassRemapper updates all internal references (field descriptors, etc.)
        val renamed = renameDecryptor(patched, decryptorClass, decryptorMethod)
        // Write with the obfuscated class name so no "StringDecryptor" appears in output
        File(outputDir, "$decryptorClass.class").writeBytes(renamed)
    }

    /**
     * Renames the class from "StringDecryptor" to [newClassName] and the "decrypt" method
     * to [newMethodName] using ASM [ClassRemapper] so that all internal references
     * (field descriptors, INVOKESTATIC calls within the class body, etc.) are updated.
     */
    private fun renameDecryptor(
        bytes: ByteArray, newClassName: String, newMethodName: String
    ): ByteArray {
        val reader = ClassReader(bytes)
        val writer = ClassWriter(0)
        val remapper = object : Remapper() {
            override fun map(internalName: String): String =
                if (internalName == "StringDecryptor") newClassName else internalName

            override fun mapMethodName(owner: String, name: String, descriptor: String): String =
                if (owner == "StringDecryptor" && name == "decrypt") newMethodName else name
        }
        reader.accept(ClassRemapper(writer, remapper), 0)
        return writer.toByteArray()
    }

    /**
     * Patches KEY_0..KEY_3 into StringDecryptor's static initialiser.
     *
     * Derives the 16-byte AES master key from [key], splits it into four Ints,
     * and injects each as an XOR of two unrelated-looking constants (arithmetic veil)
     * so no Int literal in the bytecode directly reveals a key part.
     */
    private fun patchDecryptorKey(bytes: ByteArray, key: Long): ByteArray {
        val masterKey = AesFileEncryptor.deriveAesKey(key)
        val parts     = AesFileEncryptor.splitKey(masterKey)
        val veils     = intArrayOf(0x7A3F1B2C, 0xC4E8D059.toInt(), 0x51A6F390.toInt(), 0x8B2D7E4F.toInt())

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
                            for (i in 0..3) {
                                mv.visitLdcInsn(veils[i])
                                mv.visitLdcInsn(veils[i] xor parts[i])
                                mv.visitInsn(IXOR)
                                mv.visitFieldInsn(PUTSTATIC, "StringDecryptor", "KEY_$i", "I")
                            }
                        }
                    }
                }
                return mv
            }
        }, 0)

        return writer.toByteArray()
    }

    private fun injectCryptorFilesWrapper(outputDir: File, key: Long) {
        val classLoader  = EncryptClassesTask::class.java.classLoader
        val filesName    = CryptorPlugin.deriveFilesWrapperName(key)
        val audioName    = CryptorPlugin.deriveAudioWrapperName(key)

        // ---- CryptorFilesWrapper: patch keys then rename ----
        val mainBytes = classLoader.getResourceAsStream("CryptorFilesWrapper.class")
            ?.readBytes() ?: error("CryptorFilesWrapper.class not found in plugin JAR")

        val patched = patchCryptorFilesWrapperKeys(mainBytes, key)
        File(outputDir, "$filesName.class").writeBytes(
            renameClass(patched, "CryptorFilesWrapper", filesName))

        listOf("CryptorFilesWrapper\$Companion", "CryptorFilesWrapper\$CryptorFileHandle")
            .forEach { innerName ->
                val inner = classLoader.getResourceAsStream("$innerName.class")?.readBytes()
                if (inner != null) {
                    val newName = innerName.replace("CryptorFilesWrapper", filesName)
                    File(outputDir, "$newName.class").writeBytes(
                        renameClass(inner, "CryptorFilesWrapper", filesName))
                }
            }

        // ---- CryptorAudioWrapper: rename only (no ENABLED field) ----
        val audioBytes = classLoader.getResourceAsStream("CryptorAudioWrapper.class")?.readBytes()
        if (audioBytes != null) {
            File(outputDir, "$audioName.class").writeBytes(
                renameClass(audioBytes, "CryptorAudioWrapper", audioName))
        }
        val audioCompanion = classLoader.getResourceAsStream("CryptorAudioWrapper\$Companion.class")?.readBytes()
        if (audioCompanion != null) {
            File(outputDir, "${audioName}\$Companion.class").writeBytes(
                renameClass(audioCompanion, "CryptorAudioWrapper", audioName))
        }

        // ---- AesFileEncryptor: copy as-is (used by CryptorFileHandle at runtime) ----
        // Not renamed because ProGuard updates all references consistently.
        classLoader.getResourceAsStream("AesFileEncryptor.class")?.readBytes()?.let { bytes ->
            File(outputDir, "AesFileEncryptor.class").writeBytes(bytes)
        }
    }

    /**
     * Renames all occurrences of [oldName] to [newName] inside [bytes] using ClassRemapper.
     * Updates the class declaration, field descriptors, method descriptors, and all INVOKESTATIC /
     * GETSTATIC / PUTSTATIC / NEW references consistently.
     */
    private fun renameClass(bytes: ByteArray, oldName: String, newName: String): ByteArray {
        val reader = ClassReader(bytes)
        val writer = ClassWriter(0)
        val remapper = object : Remapper() {
            override fun map(internalName: String): String =
                if (internalName.startsWith(oldName)) internalName.replace(oldName, newName)
                else internalName
        }
        reader.accept(ClassRemapper(writer, remapper), 0)
        return writer.toByteArray()
    }

    private fun patchCryptorFilesWrapperKeys(bytes: ByteArray, key: Long): ByteArray {
        val reader    = ClassReader(bytes)
        val writer    = ClassWriter(reader, ClassWriter.COMPUTE_MAXS)
        val masterKey = AesFileEncryptor.deriveAesKey(key)
        val parts     = AesFileEncryptor.splitKey(masterKey)
        // Veil constants: injected as fake unrelated integers; XOR'd at runtime to produce key parts
        val veils = intArrayOf(0x5A4F2B1C, 0xD7E3A09F.toInt(), 0x3C8B5E71, 0xF1260D84.toInt())

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
                            // Emit: KEY_i = VEIL_i XOR (VEIL_i XOR parts[i])
                            // Neither constant alone is a key part; XOR reveals it at runtime.
                            for (i in 0..3) {
                                mv.visitLdcInsn(veils[i])
                                mv.visitLdcInsn(veils[i] xor parts[i])
                                mv.visitInsn(IXOR)
                                mv.visitFieldInsn(PUTSTATIC, "CryptorFilesWrapper", "KEY_$i", "I")
                            }
                        }
                    }
                }
                return mv
            }
        }, 0)
        return writer.toByteArray()
    }

    // -----------------------------------------------------------------------
    // Gdx.files / Gdx.audio activation:
    //   • prepend wrapper install to create()V  (first launch)
    //   • prepend wrapper install to resume()V  (after Android onResume() resets them)
    //     If the Game subclass does not override resume(), synthesize one that calls
    //     super.resume() so the existing screen lifecycle is preserved.
    //
    // No string literals, no reflection — ProGuard renames both the class reference
    // in the bytecode AND the CryptorFilesWrapper class itself consistently.
    // -----------------------------------------------------------------------
    /**
     * Injects wrapper-install calls into the game's `create()` and `resume()` methods.
     *
     * Supports arbitrary class hierarchies — not just direct `Game` subclasses.
     *
     * Algorithm:
     *  1. Build a complete class-info map from every .class file in [outputDir].
     *  2. Identify all classes that extend `com/badlogic/gdx/Game` (directly or transitively).
     *  3. Find "leaf" classes: game-hierarchy classes with no known subclass in [outputDir].
     *  4. For each leaf, inject the wrapper-install preamble into `create()V` and `resume()V`.
     *     If a method does not exist in the leaf class, synthesize it with a proper `super` call
     *     so that the hierarchy's own implementation still runs after the wrappers are installed.
     *
     * This correctly handles patterns like `MyGame → GameBase → Game` where `MyGame.create()`
     * overrides `GameBase.create()` without calling `super` — wrappers are installed at the
     * most-derived entry point regardless of hierarchy depth.
     */
    private fun patchGdxFilesActivation(outputDir: File, filesWrapperName: String, audioWrapperName: String) {
        // ── Step 1: build class-info map ──────────────────────────────────────
        data class ClassInfo(
            val file:      File,
            val bytes:     ByteArray,
            val superName: String?,
            val methods:   Set<String>          // "name()descriptor" — declared methods only
        )

        val classMap = mutableMapOf<String, ClassInfo>()
        outputDir.walkTopDown().filter { it.isFile && it.extension == "class" }.forEach { f ->
            val bytes = f.readBytes()
            val cr    = ClassReader(bytes)
            val methods = mutableSetOf<String>()
            cr.accept(object : ClassVisitor(ASM9) {
                override fun visitMethod(
                    access: Int, name: String, descriptor: String,
                    signature: String?, exceptions: Array<out String>?
                ): MethodVisitor? { methods += "$name$descriptor"; return null }
            }, ClassReader.SKIP_CODE)
            classMap[cr.className] = ClassInfo(f, bytes, cr.superName, methods)
        }

        if (classMap.isEmpty()) return

        // ── Step 2: helpers ───────────────────────────────────────────────────
        fun isGameSubclass(name: String?): Boolean {
            if (name == null || name == "java/lang/Object") return false
            if (name == "com/badlogic/gdx/Game") return true
            return isGameSubclass(classMap[name]?.superName)
        }

        val gameClasses = classMap.filterValues { isGameSubclass(it.superName) }
        if (gameClasses.isEmpty()) return

        // A leaf has no other game-hierarchy class directly extending it.
        val leafClasses = gameClasses.keys.filter { cls ->
            gameClasses.keys.none { other -> other != cls && classMap[other]?.superName == cls }
        }

        // ── Step 3: patch create() in every leaf ──────────────────────────────
        for (leafClass in leafClasses) {
            val info   = classMap[leafClass]!!
            val reader = ClassReader(info.bytes)
            val writer = ClassWriter(reader, ClassWriter.COMPUTE_MAXS)
            val found  = booleanArrayOf(false)

            reader.accept(object : ClassVisitor(ASM9, writer) {
                override fun visitMethod(
                    access: Int, name: String, descriptor: String,
                    signature: String?, exceptions: Array<out String>?
                ): MethodVisitor {
                    val mv = super.visitMethod(access, name, descriptor, signature, exceptions)
                    if (name == "create" && descriptor == "()V") {
                        found[0] = true
                        return object : MethodVisitor(ASM9, mv) {
                            override fun visitCode() {
                                super.visitCode()
                                emitWrapperInstall(mv, filesWrapperName, audioWrapperName)
                            }
                        }
                    }
                    return mv
                }

                override fun visitEnd() {
                    if (!found[0]) {
                        // create() not declared in leaf — synthesise one that installs
                        // wrappers and then delegates to the superclass implementation.
                        val superName = info.superName ?: "com/badlogic/gdx/Game"
                        val mv = writer.visitMethod(ACC_PUBLIC, "create", "()V", null, null)
                        mv.visitCode()
                        emitWrapperInstall(mv, filesWrapperName, audioWrapperName)
                        mv.visitVarInsn(ALOAD, 0)
                        mv.visitMethodInsn(INVOKESPECIAL, superName, "create", "()V", false)
                        mv.visitInsn(RETURN)
                        mv.visitMaxs(0, 0)
                        mv.visitEnd()
                    }
                    super.visitEnd()
                }
            }, 0)

            info.file.writeBytes(writer.toByteArray())
        }

        // ── Step 4: patch resume() in every leaf ─────────────────────────────
        // Re-read files from disk: Step 3 may have modified them.
        for (leafClass in leafClasses) {
            val info   = classMap[leafClass]!!
            val reader = ClassReader(info.file.readBytes())
            val writer = ClassWriter(reader, ClassWriter.COMPUTE_MAXS)
            val found  = booleanArrayOf(false)

            reader.accept(object : ClassVisitor(ASM9, writer) {
                override fun visitMethod(
                    access: Int, name: String, descriptor: String,
                    signature: String?, exceptions: Array<out String>?
                ): MethodVisitor {
                    val mv = super.visitMethod(access, name, descriptor, signature, exceptions)
                    if (name == "resume" && descriptor == "()V") {
                        found[0] = true
                        return object : MethodVisitor(ASM9, mv) {
                            override fun visitCode() {
                                super.visitCode()
                                emitWrapperInstall(mv, filesWrapperName, audioWrapperName)
                            }
                        }
                    }
                    return mv
                }

                override fun visitEnd() {
                    if (!found[0]) {
                        // Synthesise resume() — reinstalls wrappers after Android's onResume()
                        // resets Gdx.audio / Gdx.files, then calls the inherited implementation.
                        val superName = info.superName ?: "com/badlogic/gdx/Game"
                        val mv = writer.visitMethod(ACC_PUBLIC, "resume", "()V", null, null)
                        mv.visitCode()
                        emitWrapperInstall(mv, filesWrapperName, audioWrapperName)
                        mv.visitVarInsn(ALOAD, 0)
                        mv.visitMethodInsn(INVOKESPECIAL, superName, "resume", "()V", false)
                        mv.visitInsn(RETURN)
                        mv.visitMaxs(0, 0)
                        mv.visitEnd()
                    }
                    super.visitEnd()
                }
            }, 0)

            info.file.writeBytes(writer.toByteArray())
        }
    }

    /**
     * Emits the two-wrapper install sequence into [mv]:
     *   Gdx.files = new [filesWrapperName](Gdx.files)
     *   Gdx.audio = new [audioWrapperName](Gdx.audio)
     *
     * Called at the top of both create()V and resume()V so that the wrappers survive
     * Android's onResume() reset of Gdx.audio / Gdx.files.
     */
    private fun emitWrapperInstall(mv: MethodVisitor, filesWrapperName: String, audioWrapperName: String) {
        // Gdx.files = new CryptorFilesWrapper(Gdx.files)
        mv.visitTypeInsn(NEW, filesWrapperName)
        mv.visitInsn(DUP)
        mv.visitFieldInsn(GETSTATIC, "com/badlogic/gdx/Gdx", "files", "Lcom/badlogic/gdx/Files;")
        mv.visitMethodInsn(INVOKESPECIAL, filesWrapperName, "<init>", "(Lcom/badlogic/gdx/Files;)V", false)
        mv.visitFieldInsn(PUTSTATIC, "com/badlogic/gdx/Gdx", "files", "Lcom/badlogic/gdx/Files;")
        // Gdx.audio = new CryptorAudioWrapper(Gdx.audio)
        // Intercepts newSound/newMusic to avoid ClassCastException on Android
        // (DefaultAndroidAudio casts FileHandle → AndroidFileHandle).
        mv.visitTypeInsn(NEW, audioWrapperName)
        mv.visitInsn(DUP)
        mv.visitFieldInsn(GETSTATIC, "com/badlogic/gdx/Gdx", "audio", "Lcom/badlogic/gdx/Audio;")
        mv.visitMethodInsn(INVOKESPECIAL, audioWrapperName, "<init>", "(Lcom/badlogic/gdx/Audio;)V", false)
        mv.visitFieldInsn(PUTSTATIC, "com/badlogic/gdx/Gdx", "audio", "Lcom/badlogic/gdx/Audio;")
    }

    // -----------------------------------------------------------------------
    // Exclusion helper
    // -----------------------------------------------------------------------
    private fun isExcluded(internalName: String, extra: List<String>): Boolean {
        if (builtinExclusions.any { internalName.startsWith(it) }) return true
        if (extra.any { internalName.startsWith(it) }) return true
        return false
    }
}
