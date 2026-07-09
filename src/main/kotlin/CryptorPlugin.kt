import com.android.build.api.variant.AndroidComponentsExtension
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.Task
import org.gradle.api.tasks.compile.AbstractCompile
import org.jetbrains.kotlin.gradle.tasks.KotlinJvmCompile
import java.io.File
import java.security.MessageDigest

class CryptorPlugin : Plugin<Project> {

    // -------------------------------------------------------------------------
    // Deterministic obfuscated name derivation
    //
    // Names are derived from the encryption key so every project using a unique
    // key gets a unique decryptor class/method name.  The derivation is stable
    // across builds (same key → same names), which keeps Gradle's build cache
    // valid. An attacker cannot guess the class/method name without knowing the key.
    // -------------------------------------------------------------------------

    companion object {
        private val NAME_CHARS = "abcdefghijklmnopqrstuvwxyz"

        /** Derive a 6-letter class name from the lower 48 bits of the key. */
        fun deriveClassName(key: Long): String = buildString(6) {
            var k = key
            repeat(6) {
                append(NAME_CHARS[((k and 0xFFL).toInt() % 26 + 26) % 26])
                k = k ushr 8
            }
        }

        /** Derive a 2-letter method name from the upper 16 bits of the key. */
        fun deriveMethodName(key: Long): String = buildString(2) {
            var k = key ushr 48
            repeat(2) {
                append(NAME_CHARS[((k and 0xFFL).toInt() % 26 + 26) % 26])
                k = k ushr 8
            }
        }

        /** Derive a 19-letter obfuscated class name for CryptorFilesWrapper from the key.
         *  Must be exactly 19 chars to match the original "CryptorFilesWrapper" length —
         *  byte-level rename in EncryptClassesTask requires equal-length replacement. */
        fun deriveFilesWrapperName(key: Long): String = buildString(19) {
            var k = key xor 0x5555555555555555L
            repeat(19) {
                append(NAME_CHARS[((k and 0xFFL).toInt() % 26 + 26) % 26])
                k = (k ushr 8) or ((k and 0xFFL) shl 56)  // rotate-right 8
            }
        }

        /** Derive a 19-letter obfuscated class name for CryptorAudioWrapper from the key.
         *  Must be exactly 19 chars to match the original "CryptorAudioWrapper" length. */
        fun deriveAudioWrapperName(key: Long): String = buildString(19) {
            var k = key xor -0x5555555555555556L  // == key XOR 0xAAAAAAAAAAAAAAAA
            repeat(19) {
                append(NAME_CHARS[((k and 0xFFL).toInt() % 26 + 26) % 26])
                k = (k ushr 8) or ((k and 0xFFL) shl 56)  // rotate-right 8
            }
        }
    }

    override fun apply(project: Project) {
        val extension = project.extensions.create(
            "cryptor",
            CryptorExtension::class.java
        )

        // Android modules: wire via AGP variant callback (must happen before afterEvaluate)
        project.plugins.withId("com.android.application") { applyAndroid(project, extension) }
        project.plugins.withId("com.android.library")     { applyAndroid(project, extension) }

        // JVM / Desktop modules: wire after ALL projects are evaluated so that
        // subproject plugin checks (hasPlugin) see the fully-resolved state.
        // Using projectsEvaluated instead of afterEvaluate because the latter
        // fires per-project — core may evaluate before lwjgl3, causing lwjgl3's
        // Cryptor plugin to be invisible during core's afterEvaluate.
        project.gradle.projectsEvaluated {
            if (!extension.enabled.get()) {
                project.logger.lifecycle("[Cryptor] enabled = false — all encryption skipped.")
                return@projectsEvaluated
            }
            val hasAndroid = project.plugins.hasPlugin("com.android.application") ||
                             project.plugins.hasPlugin("com.android.library")
            if (!hasAndroid) wireJvm(project, extension)
        }
    }

    // -------------------------------------------------------------------------
    // Android wiring
    // -------------------------------------------------------------------------
    private fun applyAndroid(project: Project, extension: CryptorExtension) {
        val androidComponents = project.extensions
            .findByType(AndroidComponentsExtension::class.java) ?: return

        // Track all variant names for class encryption wiring.
        // assetVariants is a subset — only variants that need asset encryption.
        val allVariants = mutableListOf<String>()
        val assetVariants = mutableListOf<String>()

        androidComponents.onVariants { variant ->
            if (!extension.enabled.get()) return@onVariants
            if (extension.skipDebug.get() && variant.buildType == "debug") return@onVariants

            val variantName = variant.name.replaceFirstChar { it.uppercaseChar() }
            val encryptTask = project.tasks.register(
                "encryptStrings$variantName",
                EncryptClassesTask::class.java
            ) { task ->
                task.encryptionKey.set(extension.key)
                task.excludePackages.set(extension.excludePackages)
                task.decryptorClassName.set(extension.key.map  { k -> deriveClassName(k)  })
                task.decryptorMethodName.set(extension.key.map { k -> deriveMethodName(k) })
                task.encryptStrings.set(extension.encryptStrings)
                task.runtimeDecryptorHash.set(runtimeDecryptorHash())
                // Decryptor + wrappers are injected by the JVM path on the :core module.
                // Injecting them again on Android would cause duplicate class errors
                // (R8: "Type ieuufi is defined multiple times") because :core's JAR
                // already contains them and Android depends on :core.
                task.injectDecryptor.set(false)
                task.injectFilesWrapper.set(false)
                task.outputDir.set(
                    project.layout.buildDirectory.dir("encryptedClasses/$variantName")
                )
                // outputDir is fully deleted + regenerated by transform() on every run and its
                // contents are copied out (never consumed in-place by Gradle). Tracking its
                // state across builds only exposes us to Gradle's stale-output verification,
                // which can hard-fail the up-to-date check if a previously recorded output file
                // is missing on disk (e.g. removed by a partial/interrupted build or IDE cache
                // cleanup). doNotTrackState opts this task out of that check entirely — it
                // always executes and simply regenerates outputDir from scratch, which is what
                // we want given the directory is disposable build output, not a cache asset.
                task.doNotTrackState(
                    "Cryptor: outputDir is disposable, regenerated in full every run, and copied " +
                        "out via doLast — tracking its state only risks spurious stale-output failures."
                )
            }

            // Hook lazily into the Kotlin / Java compile task for this variant.
            // Note: we do NOT call encryptTask.configure() here because Gradle does not allow
            // configuring one task while another is being realized (NamedDomainObjectProvider
            // context restriction). inputDir is @Optional so the task runs safely without it.
            project.tasks.matching {
                it.name == "compile${variantName}Kotlin" ||
                it.name == "compile${variantName}JavaWithJavac"
            }.configureEach { compileTask ->
                compileTask.finalizedBy(encryptTask)
            }

            allVariants += variantName

            if (extension.encryptAssets.get()) {
                assetVariants += variantName

                // Inject consumer ProGuard rules so R8 does not dead-code-eliminate the
                // key-derived CryptorFilesWrapper / CryptorAudioWrapper classes.
                // The plugin JAR lives on the buildscript classpath — META-INF/proguard/
                // is NOT auto-discovered there. We write the rules to a temp file and add
                // it explicitly so R8 sees them during minification.
                // allowobfuscation: R8 can still rename both classes. Obfuscation is preserved.
                val rulesContent = """
                    -keep,allowobfuscation class * implements com.badlogic.gdx.Files {
                        <init>(com.badlogic.gdx.Files);
                    }
                    -keep,allowobfuscation class * implements com.badlogic.gdx.Audio {
                        <init>(com.badlogic.gdx.Audio);
                    }
                """.trimIndent()
                val rulesFile = project.layout.buildDirectory
                    .file("cryptor/cryptor-consumer-rules.pro")
                    .get().asFile
                rulesFile.parentFile.mkdirs()
                rulesFile.writeText(rulesContent)
                variant.proguardFiles.add(project.objects.fileProperty().apply { set(rulesFile) })
            }
        }

        // Asset-encryption task wiring.
        //
        // WHY afterEvaluate here (not inside onVariants):
        //   onVariants runs DURING AGP's afterEvaluate. AGP hasn't finished creating its tasks
        //   yet when onVariants fires, so tasks.named("mergeReleaseAssets") throws.
        //   Our plugin is applied AFTER com.android.application in every consumer build.gradle,
        //   so our afterEvaluate callback is queued AFTER AGP's. By the time ours executes,
        //   all AGP tasks exist and tasks.named() is safe.
        project.afterEvaluate {
            if (!extension.enabled.get()) return@afterEvaluate

            // Wire class encryption: set inputDir to each variant's compile output
            // and copy encrypted/injected classes back so the dex step picks them up.
            for (variantName in allVariants) {
                val compileTask = project.tasks.findByName("compile${variantName}Kotlin")
                    ?: project.tasks.findByName("compile${variantName}JavaWithJavac")
                    ?: continue

                val compileDirProvider = resolveDestinationDirProvider(compileTask)
                if (compileDirProvider != null) {
                    project.tasks.named("encryptStrings${variantName}", EncryptClassesTask::class.java) { task ->
                        task.inputDir.set(compileDirProvider)
                        task.doLast {
                            val encryptedDir = task.outputDir.get().asFile
                            val targetDir = compileDirProvider.get().asFile
                            if (!encryptedDir.exists()) return@doLast
                    encryptedDir.walkTopDown().filter { it.isFile && it.extension == "class" }.forEach { cls ->
                                val rel = cls.relativeTo(encryptedDir)
                                val dest = File(targetDir, rel.path)
                                dest.parentFile?.mkdirs()
                                cls.copyTo(dest, overwrite = true)
                            }
                        }
                    }
                } else {
                    project.logger.warn("[Cryptor] Could not find compile output for variant $variantName — classes will not be encrypted.")
                }
            }

            // Wire asset encryption (in-place via doLast on mergeXxxAssets)
            if (!extension.encryptAssets.get()) return@afterEvaluate

            for (variantName in assetVariants) {
                val lcVariant = variantName.replaceFirstChar { it.lowercaseChar() }
                val mergedAssetsPath = "intermediates/assets/$lcVariant/merge${variantName}Assets"

                val encryptAssetsTask = project.tasks.register(
                    "cryptorEncryptAssets$variantName"
                ) { t ->
                    t.group = "cryptor"
                    t.description = "Encrypts merged Android assets in-place for $variantName"
                    val mergedDir = project.layout.buildDirectory.dir(mergedAssetsPath)
                    // No inputs.dir() — Gradle 9 strictly validates declared input directories exist
                    // at configuration time, which fails for AGP-created dirs. Since we use
                    // upToDateWhen { false } the task always runs; the doLast guards against
                    // the directory not existing.
                    t.outputs.upToDateWhen { false }
                    t.doLast {
                        val dir = mergedDir.get().asFile
                        if (!dir.exists()) return@doLast
                        val masterKey = AesFileEncryptor.deriveAesKey(extension.key.get())
                        val exts = extension.assetExtensions.get().map { it.lowercase() }.toSet()
                        dir.walkTopDown().filter { it.isFile }.forEach { src ->
                            if (src.extension.lowercase() !in exts) return@forEach
                            val raw = src.readBytes()
                            if (AesFileEncryptor.hasMagic(raw, masterKey)) return@forEach
                            val relPath = src.relativeTo(dir).path.replace(java.io.File.separatorChar, '/')
                            src.writeBytes(AesFileEncryptor.encrypt(raw, masterKey, relPath))
                        }
                    }
                }

                // AGP tasks are guaranteed to exist here — safe to use tasks.named()
                project.tasks.named("merge${variantName}Assets").configure {
                    it.finalizedBy(encryptAssetsTask)
                }
                listOf(
                    "package$variantName",
                    "bundle${variantName}Aar",
                    "bundle${variantName}",
                    // compressReleaseAssets runs between mergeReleaseAssets and packageRelease.
                    // It reads from the mergeReleaseAssets output directory, so it must depend on
                    // our encrypt task (which also writes to that directory) to ensure assets are
                    // encrypted before compressReleaseAssets copies them to its own output dir.
                    "compress${variantName}Assets"
                ).forEach { tName ->
                    project.tasks.matching { it.name == tName }
                        .configureEach { it.dependsOn(encryptAssetsTask) }
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Stale-cache guard: hash of the bundled StringDecryptor.class
    // -------------------------------------------------------------------------
    private fun runtimeDecryptorHash(): String {
        val bytes = CryptorPlugin::class.java.classLoader
            .getResourceAsStream("StringDecryptor.class")
            ?.readBytes() ?: ByteArray(0)
        return MessageDigest.getInstance("MD5").digest(bytes)
            .joinToString("") { "%02x".format(it) }
    }

    // -------------------------------------------------------------------------
    // JVM / Desktop wiring
    // -------------------------------------------------------------------------
    private fun wireJvm(project: Project, extension: CryptorExtension) {
        val kotlinTask = project.tasks.findByName("compileKotlin")
        val javaTask   = project.tasks.findByName("compileJava") as? AbstractCompile

        if (kotlinTask == null && javaTask == null) {
            project.logger.warn("[Cryptor] No compileKotlin or compileJava task found — skipping.")
            return
        }

        // Collect all compile-output directories.
        // KGP 1.x: KotlinCompile extends AbstractCompile — direct cast works.
        // KGP 2.x: KotlinJvmCompile does NOT extend AbstractCompile — use reflection.
        val compileTasks  = mutableListOf<Task>()
        val compileDirs   = mutableListOf<File>()

        kotlinTask?.let { t ->
            val dir = resolveDestinationDir(t)
            if (dir != null) {
                compileTasks.add(t)
                compileDirs.add(dir)
            } else {
                project.logger.warn("[encryptStrings] Could not resolve destinationDirectory for compileKotlin — Kotlin classes will not be encrypted.")
            }
        }
        javaTask?.let { t ->
            val dir = t.destinationDirectory.orNull?.asFile
            if (dir != null && dir !in compileDirs) {
                compileTasks.add(t)
                compileDirs.add(dir)
            }
        }

        if (compileTasks.isEmpty()) {
            project.logger.warn("[Cryptor] No usable compile outputs found — skipping.")
            return
        }

        // ---- Also include direct JVM implementation-dependency subprojects (e.g. :core) ----
        // This ensures patchGdxFilesActivation finds Game subclasses that live in :core, and
        // that all game-logic strings get encrypted — not just the launcher module's.
        // Use rootProject.subprojects instead of ProjectDependency.getDependencyProject()
        // to stay compatible with Gradle 8+ (where getDependencyProject() is restricted).
        // NOTE: Only include subprojects that do NOT apply the Cryptor plugin themselves.
        // Subprojects with their own Cryptor task already handle string encryption + patching.
        // Including them here would cause double-encryption.
        project.rootProject.subprojects
            .filter { sub ->
                sub != project &&
                !sub.plugins.hasPlugin("com.android.application") &&
                !sub.plugins.hasPlugin("com.android.library") &&
                !sub.plugins.hasPlugin("com.github.MRZ07.Cryptor-Gradle-Plugin")
            }
            .forEach { sub ->
                sub.tasks.findByName("compileKotlin")?.let { t ->
                    resolveDestinationDir(t)?.let { dir ->
                        if (dir !in compileDirs) { compileTasks += t; compileDirs += dir }
                    }
                }
                (sub.tasks.findByName("compileJava") as? AbstractCompile)?.let { t ->
                    t.destinationDirectory.orNull?.asFile?.let { dir ->
                        if (dir !in compileDirs) { compileTasks += t; compileDirs += dir }
                    }
                }
            }

        val encryptTask = project.tasks.register("cryptorEncryptStrings", EncryptClassesTask::class.java) { task ->
            task.encryptionKey.set(extension.key)
            task.excludePackages.set(extension.excludePackages)
            task.decryptorClassName.set(extension.key.map  { k -> deriveClassName(k)  })
            task.decryptorMethodName.set(extension.key.map { k -> deriveMethodName(k) })
            task.encryptStrings.set(extension.encryptStrings)
            task.injectFilesWrapper.set(extension.encryptAssets)
            task.runtimeDecryptorHash.set(runtimeDecryptorHash())
            task.inputDirs.from(*compileDirs.toTypedArray())
            task.outputDir.set(project.layout.buildDirectory.dir("encryptedClasses"))
            // See the matching comment in applyAndroid(): outputDir is disposable, fully
            // regenerated every run, and copied out into compileDirs via doLast. Tracking its
            // state exposes us to Gradle's stale-output verification hard-failing when a
            // previously recorded output file is missing on disk (partial/interrupted build,
            // IDE cache cleanup, etc.) — doNotTrackState opts out of that check.
            task.doNotTrackState(
                "Cryptor: outputDir is disposable, regenerated in full every run, and copied " +
                    "out via doLast — tracking its state only risks spurious stale-output failures."
            )
        }

        compileTasks.forEach { it.finalizedBy(encryptTask) }

        // Copy encrypted/injected class files back to their source compile-output
        // directories so that non-JAR consumers (e.g. RoboVM, IDE run configs)
        // also see the transformed classes.
        // Injected class names (AesFileEncryptor, wrappers, decryptor) are ONLY copied
        // to the FIRST compileDir (the project's own output). Copying them to other
        // subproject dirs would cause duplicate entries when those subprojects build
        // their own JARs (e.g. :ios:jar picking up AesFileEncryptor.class from :core
        // plus its own compile dir).
        val firstCompileDir = compileDirs.firstOrNull()
        encryptTask.configure { task ->
            compileDirs.forEach { compileDir ->
                val isPrimary = compileDir == firstCompileDir
                task.doLast {
                    val encryptedDir = task.outputDir.get().asFile
                    if (!encryptedDir.exists()) return@doLast
                    val key = task.encryptionKey.get()
                    val decryptName = task.decryptorClassName.orNull ?: ""
                    val filesName = CryptorPlugin.deriveFilesWrapperName(key)
                    val audioName = CryptorPlugin.deriveAudioWrapperName(key)
                    encryptedDir.walkTopDown().filter { it.isFile && it.extension == "class" }.forEach { cls ->
                        val rel = cls.relativeTo(encryptedDir)
                        val name = cls.name
                        val isInjected = name == "AesFileEncryptor.class" ||
                            name == "$decryptName.class" ||
                            name.startsWith(filesName) ||
                            name.startsWith(audioName) ||
                            name.startsWith("CryptorFilesWrapper") ||
                            name.startsWith("CryptorAudioWrapper")
                        if (!isPrimary) return@forEach
                        val dest = File(compileDir, rel.path)
                        dest.parentFile?.mkdirs()
                        cls.copyTo(dest, overwrite = true)
                    }
                }
            }
        }

        // Register the asset-encryption task.
        // Raw assets intentionally remain in resources.srcDirs so that IDE runs and the
        // Gradle `run` task can load them without CryptorFilesWrapper being active.
        // The JAR task below wires in the encrypted versions and excludes the raw copies.
        var encryptAssetsTask: org.gradle.api.tasks.TaskProvider<EncryptAssetsTask>? = null

        if (extension.encryptAssets.get() && extension.assetsDir.isPresent) {
            val sourceSets = project.extensions.findByName("sourceSets")
                as? org.gradle.api.tasks.SourceSetContainer
            if (sourceSets?.findByName("main") != null) {
                encryptAssetsTask = project.tasks.register(
                    "cryptorEncryptAssets", EncryptAssetsTask::class.java
                ) { task ->
                    task.inputDir.set(extension.assetsDir)
                    task.outputDir.set(project.layout.buildDirectory.dir("encryptedAssets"))
                    task.encryptionKey.set(extension.key)
                    task.assetExtensions.set(extension.assetExtensions)
                }
            } else {
                project.logger.warn("[Cryptor] Could not find main SourceSet — asset encryption skipped.")
            }
        }

        project.plugins.withId("java") {
            project.tasks.named("jar", org.gradle.api.tasks.bundling.Jar::class.java) { jar ->
                jar.dependsOn(encryptTask)
                // Non-core JVM modules (ios, lwjgl3) depend on :core which already
                // carries AesFileEncryptor.class and the injected wrappers. Excluding
                // duplicates from the encrypt-task output keeps the JAR clean.
                jar.from(encryptTask.flatMap { it.outputDir })
                jar.exclude { details ->
                    compileDirs.any { dir -> details.file.startsWith(dir) }
                }

                encryptAssetsTask?.let { assetsTask ->
                    // Include encrypted assets in the JAR in place of the raw copies
                    val encExtensions = extension.assetExtensions.get().toSet()
                    val resourcesMain = project.layout.buildDirectory.dir("resources/main").get().asFile
                    jar.dependsOn(assetsTask)
                    jar.from(assetsTask.flatMap { it.outputDir })
                    // Exclude the raw asset files processResources copied to build/resources/main/
                    // so only encrypted versions from build/encryptedAssets/ land in the JAR
                    jar.exclude { fileDetails ->
                        fileDetails.file.extension in encExtensions &&
                            fileDetails.file.canonicalPath.startsWith(
                                resourcesMain.canonicalPath + java.io.File.separator
                            )
                    }
                }
            }
        }
    }

    /**
     * Resolves the compile-output directory as a [Provider] from a task.
     */
    private fun resolveDestinationDirProvider(task: Task): org.gradle.api.file.DirectoryProperty? {
        (task as? AbstractCompile)?.destinationDirectory?.let { return it }
        (task as? KotlinJvmCompile)?.destinationDirectory?.let { return it }
        return null
    }

    /**
     * Resolves the compile-output directory from a task.
     *
     * KGP 1.x: [KotlinJvmCompile] extends [AbstractCompile] — first branch hits.
     * KGP 2.x: [KotlinJvmCompile] no longer extends [AbstractCompile] but it still
     *          implements [KotlinJvmCompile] which exposes [destinationDirectory] directly.
     */
    private fun resolveDestinationDir(task: Task): File? {
        (task as? AbstractCompile)?.destinationDirectory?.orNull?.asFile?.let { return it }
        (task as? KotlinJvmCompile)?.destinationDirectory?.orNull?.asFile?.let { return it }
        return null
    }
}
