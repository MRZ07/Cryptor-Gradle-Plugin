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
