import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.*
import java.io.File
import java.util.Locale

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
        val input     = inputDir.get().asFile
        val output    = outputDir.get().asFile
        val exts      = assetExtensions.get().map { it.lowercase(Locale.ROOT) }.toSet()
        val masterKey = AesFileEncryptor.deriveAesKey(encryptionKey.get())

        output.deleteRecursively()
        output.mkdirs()

        input.walkTopDown().filter { it.isFile }.forEach { src ->
            val relative = src.relativeTo(input)
            val dest     = File(output, relative.path)
            dest.parentFile.mkdirs()

            if (src.extension.lowercase(Locale.ROOT) in exts) {
                val raw = src.readBytes()
                val relPath = relative.path.replace(File.separatorChar, '/')
                encryptAsset(raw, dest, relPath, masterKey)
            } else {
                src.copyTo(dest, overwrite = true)
            }
        }
    }

    /**
     * Fails the build when an encrypted asset does not decrypt back to its source bytes.
     *
     * The runtime can only report corruption after a user installs the app; a broken key, a
     * truncated write or a format drift must stop the build instead.
     */
    companion object {
        /** Shared JVM/Android build-time implementation for one configured asset. */
        internal fun encryptAsset(raw: ByteArray, dest: File, relPath: String, masterKey: ByteArray) {
            if (AesFileEncryptor.hasMagicPrefix(raw, masterKey)) {
                if (!AesFileEncryptor.isWellFormed(raw)) {
                    throw GradleException(
                        "Cryptor: asset '$relPath' is encrypted but not in the current asset format " +
                            "(stale output from an older Cryptor version or a truncated file). Clean the build and rebuild."
                    )
                }
                dest.writeBytes(raw)
                return
            }

            val encrypted = AesFileEncryptor.encrypt(raw, masterKey, relPath)
            dest.writeBytes(encrypted)
            verifyRoundTrip(relPath, raw, encrypted, masterKey)
        }

        private fun verifyRoundTrip(
            relativePath: String,
            plaintext: ByteArray,
            encrypted: ByteArray,
            masterKey: ByteArray,
        ) {
            val decrypted = try {
                AesFileEncryptor.decrypt(encrypted, masterKey, relativePath)
            } catch (failure: RuntimeException) {
                throw GradleException(
                    "Cryptor: asset '$relativePath' does not decrypt back to its source (${failure.message})",
                    failure
                )
            }
            if (!decrypted.contentEquals(plaintext)) {
                throw GradleException(
                    "Cryptor: asset '$relativePath' does not decrypt back to its source " +
                        "(${plaintext.size} source bytes, ${decrypted.size} decrypted bytes)"
                )
            }
        }
    }
}
