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
     * with KEY and ENABLED patched to the real values.
     */
    @get:Input
    @get:Optional
    abstract val injectFilesWrapper: Property<Boolean>

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

        sources.forEach sourceLoop@{ inputRoot ->
            inputRoot.walkTopDown().filter { it.isFile }.forEach fileLoop@{ classFile ->
                val relative = classFile.relativeTo(inputRoot)
                // Resolve destination; skip if already written by a previous source dir
                val dest = File(output, relative.path)
                if (dest.exists()) return@fileLoop
                dest.parentFile?.mkdirs()

                if (classFile.extension != "class") {
                    classFile.copyTo(dest)
                    return@fileLoop
                }

                val internalName = relative.path.removeSuffix(".class").replace(File.separatorChar, '/')
                if (isExcluded(internalName, allExclusions)) {
                    classFile.copyTo(dest)
                    return@fileLoop
                }

                val doEncrypt = encryptStrings.orElse(true).get()
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

            // Encrypt the string and encode the result as an ISO-8859-1 string literal.
            // ISO-8859-1 is a bijective byte↔char mapping — all 256 byte values round-trip
            // correctly, so the encrypted bytes survive as a JVM string constant.
            // This approach replaces O(N) inline bytecode with just two instructions,
            // completely avoiding the JVM 64KB method-size limit.
            val encrypted = XorEncryptor.encrypt(value, key)
            val encryptedString = String(encrypted, Charsets.ISO_8859_1)

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
     * Injects `KEY = <realKey>` at the start of StringDecryptor's static initializer.
     *
     * The Kotlin compiler omits `LCONST_0; PUTSTATIC KEY` when the placeholder is 0L
     * (because 0 is already the field default), so searching for LCONST_0 never works.
     * Instead we unconditionally prepend `LDC key; PUTSTATIC KEY` to <clinit>.
     *
     * NOTE: operates on the original "StringDecryptor" name; [renameDecryptor] is called
     * afterwards and updates the PUTSTATIC owner via ClassRemapper.
     */
    private fun patchDecryptorKey(bytes: ByteArray, key: Long): ByteArray {
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
                            // Inject: KEY = <realKey> — ClassRemapper will update the owner
                            mv.visitLdcInsn(key)
                            mv.visitFieldInsn(PUTSTATIC, "StringDecryptor", "KEY", "J")
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

        // ---- CryptorAudioWrapper: patch enabled then rename ----
        val audioBytes = classLoader.getResourceAsStream("CryptorAudioWrapper.class")?.readBytes()
        if (audioBytes != null) {
            File(outputDir, "$audioName.class").writeBytes(
                renameClass(patchCryptorAudioWrapperEnabled(audioBytes), "CryptorAudioWrapper", audioName))
        }
        val audioCompanion = classLoader.getResourceAsStream("CryptorAudioWrapper\$Companion.class")?.readBytes()
        if (audioCompanion != null) {
            File(outputDir, "${audioName}\$Companion.class").writeBytes(
                renameClass(audioCompanion, "CryptorAudioWrapper", audioName))
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

    /**
     * Prepends `ENABLED = true` to CryptorAudioWrapper's static initializer so that
     * the wrapper is active at runtime in encrypted builds.
     */
    private fun patchCryptorAudioWrapperEnabled(bytes: ByteArray): ByteArray {
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
                            mv.visitInsn(ICONST_1)
                            mv.visitFieldInsn(PUTSTATIC, "CryptorAudioWrapper", "ENABLED", "Z")
                        }
                    }
                }
                return mv
            }
        }, 0)

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
    private fun patchGdxFilesActivation(outputDir: File, filesWrapperName: String, audioWrapperName: String) {
        // Pass 1: find the concrete class that extends com/badlogic/gdx/Game
        val targetFile = outputDir.walkTopDown()
            .filter { it.isFile && it.extension == "class" }
            .firstOrNull { ClassReader(it.readBytes()).superName == "com/badlogic/gdx/Game" }
            ?: return  // not a LibGDX game project — skip silently

        // Pass 2: patch create()V and resume()V; synthesize resume()V if absent.
        val originalBytes = targetFile.readBytes()
        val reader = ClassReader(originalBytes)
        val writer = ClassWriter(reader, ClassWriter.COMPUTE_MAXS)

        // Mutable flag — captured in array so it's accessible inside the anonymous ClassVisitor.
        val resumeFound = booleanArrayOf(false)

        reader.accept(object : ClassVisitor(ASM9, writer) {
            override fun visitMethod(
                access: Int, name: String, descriptor: String,
                signature: String?, exceptions: Array<out String>?
            ): MethodVisitor {
                val mv = super.visitMethod(access, name, descriptor, signature, exceptions)
                if ((name == "create" || name == "resume") && descriptor == "()V") {
                    if (name == "resume") resumeFound[0] = true
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
                // Synthesize resume()V when the subclass does not override it.
                // AndroidApplication.onResume() resets Gdx.audio / Gdx.files to the bare
                // Android implementations before ApplicationListener.resume() is called.
                // We reinstall the wrappers at the top of resume() to keep decryption active
                // across pause / resume cycles (e.g. going to home screen and back).
                if (!resumeFound[0]) {
                    val mv = writer.visitMethod(ACC_PUBLIC, "resume", "()V", null, null)
                    mv.visitCode()
                    emitWrapperInstall(mv, filesWrapperName, audioWrapperName)
                    // super.resume() — preserves the existing Game screen lifecycle
                    mv.visitVarInsn(ALOAD, 0)
                    mv.visitMethodInsn(INVOKESPECIAL, "com/badlogic/gdx/Game", "resume", "()V", false)
                    mv.visitInsn(RETURN)
                    mv.visitMaxs(0, 0)  // recomputed by COMPUTE_MAXS
                    mv.visitEnd()
                }
                super.visitEnd()
            }
        }, 0)

        targetFile.writeBytes(writer.toByteArray())
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
