import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.*
import org.objectweb.asm.*
import org.objectweb.asm.Opcodes.*
import org.objectweb.asm.commons.ClassRemapper
import org.objectweb.asm.commons.LocalVariablesSorter
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
     * When true (default), the string decryptor class is injected into the output.
     * Set to false on modules whose dependency already contains the decryptor
     * (e.g. Android modules where :core's JAR already carries it) to avoid
     * 'Type defined multiple times' R8 errors.
     */
    @get:Input
    @get:Optional
    abstract val injectDecryptor: Property<Boolean>

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

        // Collect all source directories to process
        val sources = mutableListOf<File>()
        inputDirs.files.filter { it.isDirectory }.forEach { sources.add(it) }
        inputDir.orNull?.asFile?.takeIf { it.isDirectory && it !in sources }?.let { sources.add(it) }

        // In-place mode: when output directory equals one of the source directories,
        // modify class files directly without deleting anything.
        val inPlace = sources.any { it.canonicalPath == output.canonicalPath }

        if (!inPlace) {
            output.deleteRecursively()
            output.mkdirs()
        }

        // Hoist constant: evaluated once per task run, not once per file in the parallel loop.
        val doEncrypt = encryptStrings.orElse(true).get()

        sources.forEach { inputRoot ->
            inputRoot.walkTopDown().filter { it.isFile }.toList()
                .parallelStream()
                .forEach { classFile ->
                    val relative = classFile.relativeTo(inputRoot)
                    val dest = if (inPlace) classFile else File(output, relative.path)
                    if (!inPlace && dest.exists()) return@forEach
                    if (!inPlace) dest.parentFile?.mkdirs()

                    if (classFile.extension != "class") {
                        if (!inPlace) classFile.copyTo(dest)
                        return@forEach
                    }

                    val internalName = relative.path.removeSuffix(".class").replace(File.separatorChar, '/')
                    if (isExcluded(internalName, allExclusions)) {
                        if (!inPlace) classFile.copyTo(dest)
                        return@forEach
                    }

                    if (doEncrypt) {
                        dest.writeBytes(transformClass(classFile.readBytes(), key, decryptClass, decryptMethod))
                    } else if (!inPlace) {
                        classFile.copyTo(dest)
                    }
                }
        }

        if (encryptStrings.orElse(true).get() && injectDecryptor.orElse(true).get()) {
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
    ): ByteArray = EncryptClassesTask.transformClass(bytes, key, decryptorClass, decryptorMethod)

    companion object {
        internal fun transformClass(
            bytes: ByteArray, key: Long,
            decryptorClass: String, decryptorMethod: String
        ): ByteArray {
            val reader = ClassReader(bytes)
            // COMPUTE_FRAMES is required: the indy→StringBuilder rewrite adds new locals, and
            // without recomputing the StackMapTable the frames at branch targets go stale
            // (VerifyError "Inconsistent stackmap frames"). COMPUTE_MAXS alone only recomputes
            // max_stack/max_locals, leaving the original frames in place.
            val writer = object : ClassWriter(ClassWriter.COMPUTE_MAXS or ClassWriter.COMPUTE_FRAMES) {
                override fun getCommonSuperClass(type1: String, type2: String): String {
                    // COMPUTE_FRAMES needs the class hierarchy, but the plugin runs before
                    // dependencies are on the classpath (e.g. libGDX is compileOnly). Fall back
                    // to java/lang/Object instead of throwing TypeNotPresentException.
                    return try {
                        super.getCommonSuperClass(type1, type2)
                    } catch (_: RuntimeException) {
                        "java/lang/Object"
                    }
                }
            }
            reader.accept(EncryptingClassVisitor(writer, key, decryptorClass, decryptorMethod), ClassReader.EXPAND_FRAMES)
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
                val sorter = LocalVariablesSorter(
                    access, descriptor,
                    super.visitMethod(access, name, descriptor, signature, exceptions)
                )
                return EncryptingMethodVisitor(sorter, sorter, key, decryptorClass, decryptorMethod)
            }
        }

        private class EncryptingMethodVisitor(
            mv: MethodVisitor,
            private val sorter: LocalVariablesSorter,
            private val key: Long,
            private val decryptorClass: String,
            private val decryptorMethod: String
        ) : MethodVisitor(ASM9, mv) {

            /** Modified-UTF-8 byte count for an ISO-8859-1 [s] without encoding it. */
            private fun modifiedUtf8Length(s: String): Int {
                var len = 0
                for (c in s) {
                    len += when {
                        c.code in 0x0001..0x007F -> 1
                        c.code == 0x0000 || c.code in 0x0080..0x07FF -> 2
                        else -> 3
                    }
                }
                return len
            }

            override fun visitLdcInsn(value: Any?) {
                if (value !is String) {
                    super.visitLdcInsn(value)
                    return
                }
                emitEncryptedLdc(mv, value)
            }

            /**
             * Rewrites a `StringConcatFactory` invokedynamic site (Kotlin string templates
             * compile to these) into a stack-neutral `StringBuilder` block whose literal
             * segments go through [emitEncryptedLdc]. Malformed recipes fall back to the
             * original invokedynamic (fail-open).
             */
            override fun visitInvokeDynamicInsn(
                name: String, descriptor: String, bsm: Handle, vararg bsmArgs: Any?
            ) {
                if (bsm.owner != "java/lang/invoke/StringConcatFactory" ||
                    bsm.name !in setOf("makeConcatWithConstants", "makeConcat")
                ) {
                    super.visitInvokeDynamicInsn(name, descriptor, bsm, *bsmArgs)
                    return
                }

                val argTypes = Type.getArgumentTypes(descriptor)
                val recipe = when (bsm.name) {
                    "makeConcat" -> "\u0001".repeat(argTypes.size)
                    else -> bsmArgs.getOrNull(0) as? String ?: return run {
                        super.visitInvokeDynamicInsn(name, descriptor, bsm, *bsmArgs)
                    }
                }
                val constants = bsmArgs.drop(1)
                val segments = parseRecipe(recipe, argTypes.size, constants.size) ?: return run {
                    super.visitInvokeDynamicInsn(name, descriptor, bsm, *bsmArgs)
                }

                // 1. Save args: descriptor order argTypes[0..n-1]; on stack argTypes[n-1] deepest.
                val slots = argTypes.map { sorter.newLocal(it) }
                for (i in argTypes.indices.reversed()) {
                    mv.visitVarInsn(argTypes[i].getOpcode(Opcodes.ISTORE), slots[i])
                }

                // 2. StringBuilder
                mv.visitTypeInsn(Opcodes.NEW, "java/lang/StringBuilder")
                mv.visitInsn(Opcodes.DUP)
                mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false)

                // 3. Segments
                for (seg in segments) when (seg) {
                    is Segment.Literal -> {
                        emitEncryptedLdc(mv, seg.text)
                        emitAppend(mv, "(Ljava/lang/String;)Ljava/lang/StringBuilder;")
                    }
                    is Segment.Arg -> {
                        mv.visitVarInsn(argTypes[seg.index].getOpcode(Opcodes.ILOAD), slots[seg.index])
                        emitAppend(mv, appendDescriptorFor(argTypes[seg.index]))
                    }
                    is Segment.Const -> {
                        emitEncryptedLdc(mv, java.lang.String.valueOf(constants[seg.index]))
                        emitAppend(mv, "(Ljava/lang/String;)Ljava/lang/StringBuilder;")
                    }
                }

                // 4. toString
                mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false)
            }

            private fun emitEncryptedLdc(mv: MethodVisitor, value: String) {
                val saltBytes = XorEncryptor.encrypt(value, key)
                val encryptedString = String(saltBytes, Charsets.ISO_8859_1)
                if (modifiedUtf8Length(encryptedString) > 65535) {
                    mv.visitLdcInsn(value)
                    return
                }
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
        // StringConcatFactory recipe parsing + StringBuilder append helpers
        // -----------------------------------------------------------------------
        private sealed class Segment {
            class Literal(val text: String) : Segment()
            class Arg(val index: Int) : Segment()
            class Const(val index: Int) : Segment()
        }

        private fun parseRecipe(
            recipe: String, argCount: Int, constCount: Int
        ): List<Segment>? {
            val out = mutableListOf<Segment>()
            val run = StringBuilder()
            var argIdx = 0
            var constIdx = 0
            for (c in recipe) when (c) {
                '\u0001' -> {
                    if (run.isNotEmpty()) { out += Segment.Literal(run.toString()); run.setLength(0) }
                    out += Segment.Arg(argIdx++)
                }
                '\u0002' -> {
                    if (run.isNotEmpty()) { out += Segment.Literal(run.toString()); run.setLength(0) }
                    if (constIdx >= constCount) return null
                    out += Segment.Const(constIdx++)
                }
                else -> run.append(c)
            }
            if (run.isNotEmpty()) out += Segment.Literal(run.toString())
            return if (argIdx == argCount && constIdx == constCount) out else null
        }

        private fun appendDescriptorFor(type: Type): String = when (type.sort) {
            Type.INT, Type.BYTE, Type.SHORT -> "(I)Ljava/lang/StringBuilder;"
            Type.LONG -> "(J)Ljava/lang/StringBuilder;"
            Type.FLOAT -> "(F)Ljava/lang/StringBuilder;"
            Type.DOUBLE -> "(D)Ljava/lang/StringBuilder;"
            Type.CHAR -> "(C)Ljava/lang/StringBuilder;"
            Type.BOOLEAN -> "(Z)Ljava/lang/StringBuilder;"
            else -> "(Ljava/lang/Object;)Ljava/lang/StringBuilder;"
        }

        private fun emitAppend(mv: MethodVisitor, argDesc: String) {
            mv.visitMethodInsn(
                INVOKEVIRTUAL, "java/lang/StringBuilder", "append", argDesc, false
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
     * Patches KEY into StringDecryptor's static initializer.
     *
     * The Kotlin compiler omits LCONST_0; PUTSTATIC KEY when the placeholder is 0L
     * (because 0 is already the field default), so we unconditionally prepend
     * LDC key; PUTSTATIC KEY to <clinit>.
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

        // ---- CryptorAudioWrapper: rename self AND update CryptorFilesWrapper cross-reference ----
        // CryptorAudioWrapper.keyHash() calls CryptorFilesWrapper.masterKey(). If we only rename
        // CryptorAudioWrapper → audioName but leave the internal CryptorFilesWrapper reference
        // intact, R8 reports "Missing class CryptorFilesWrapper" and the app crashes with
        // NoClassDefFoundError on the first newSound()/newMusic() call.
        val audioBytes = classLoader.getResourceAsStream("CryptorAudioWrapper.class")?.readBytes()
        if (audioBytes != null) {
            val renamed = renameClass(audioBytes, "CryptorAudioWrapper", audioName)
            val crossFixed = renameClass(renamed, "CryptorFilesWrapper", filesName)
            File(outputDir, "$audioName.class").writeBytes(crossFixed)
        }
        val audioCompanion = classLoader.getResourceAsStream("CryptorAudioWrapper\$Companion.class")?.readBytes()
        if (audioCompanion != null) {
            val renamed = renameClass(audioCompanion, "CryptorAudioWrapper", audioName)
            val crossFixed = renameClass(renamed, "CryptorFilesWrapper", filesName)
            File(outputDir, "${audioName}\$Companion.class").writeBytes(crossFixed)
        }

        // ---- AesFileEncryptor: copy as-is (used by CryptorFileHandle at runtime) ----
        // Not renamed because ProGuard updates all references consistently.
        classLoader.getResourceAsStream("AesFileEncryptor.class")?.readBytes()?.let { bytes ->
            File(outputDir, "AesFileEncryptor.class").writeBytes(bytes)
        }
    }

    /**
     * Renames all occurrences of [oldName] to [newName] inside [bytes].
     *
     * Uses a simple byte-level replacement — no ASM required.
     * Requires [newName] to be the SAME byte length as [oldName] so
     * that constant-pool offsets are preserved.
     */
    private fun renameClass(bytes: ByteArray, oldName: String, newName: String): ByteArray {
        val oldBytes = oldName.toByteArray(Charsets.UTF_8)
        val newBytes = newName.toByteArray(Charsets.UTF_8)
        require(oldBytes.size == newBytes.size) {
            "renameClass: oldName '$oldName' (${oldBytes.size} bytes) and newName '$newName' (${newBytes.size} bytes) must have the same UTF-8 byte length"
        }
        val result = bytes.copyOf()
        var i = 0
        while (i <= result.size - oldBytes.size) {
            var match = true
            for (j in oldBytes.indices) {
                if (result[i + j] != oldBytes[j]) { match = false; break }
            }
            if (match) {
                System.arraycopy(newBytes, 0, result, i, newBytes.size)
                i += oldBytes.size
            } else {
                i++
            }
        }
        return result
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
