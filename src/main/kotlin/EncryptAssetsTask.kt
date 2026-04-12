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
        val key    = encryptionKey.get()
        val exts   = assetExtensions.get().map { it.lowercase() }.toSet()

        output.deleteRecursively()
        output.mkdirs()

        input.walkTopDown().filter { it.isFile }.forEach { src ->
            val relative = src.relativeTo(input)
            val dest = File(output, relative.path)
            dest.parentFile.mkdirs()

            if (src.extension.lowercase() in exts) {
                // Prepend magic header so CryptorFilesWrapper can identify encrypted files
                val encrypted = XorEncryptor.encrypt(src.readBytes(), key)
                dest.writeBytes(MAGIC_HEADER + encrypted)
            } else {
                src.copyTo(dest, overwrite = true)
            }
        }
    }

    companion object {
        /** 4-byte magic header prepended to every encrypted asset. */
        val MAGIC_HEADER = byteArrayOf(0xC0.toByte(), 0xDE.toByte(), 0xBA.toByte(), 0xBE.toByte())
    }
}
