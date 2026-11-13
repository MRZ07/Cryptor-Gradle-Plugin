import java.io.File
import org.gradle.testfixtures.ProjectBuilder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertTrue

class EncryptAssetsTaskTest {

    @Test
    fun encryptsConfiguredFilesPreservingPathsAndSourceBytes() {
        val root = File(
            System.getProperty("java.io.tmpdir"),
            "cryptor-assets-test-${System.nanoTime()}"
        )
        val input = File(root, "input")
        val output = File(root, "encrypted")
        val image = File(input, "ui/nested/icon.png")
        val config = File(input, "data/settings.properties")
        val imageBytes = byteArrayOf(1, 2, 3, 4, 5)
        val configBytes = "plain config".toByteArray(Charsets.UTF_8)
        image.parentFile.mkdirs()
        config.parentFile.mkdirs()
        image.writeBytes(imageBytes)
        config.writeBytes(configBytes)

        try {
            val task = ProjectBuilder.builder().build().tasks.create(
                "encryptAssets",
                EncryptAssetsTask::class.java
            )
            val key = 0x1234567890ABCDEFL
            task.inputDir.set(input)
            task.outputDir.set(output)
            task.encryptionKey.set(key)
            task.assetExtensions.set(listOf("png"))

            task.encrypt()

            val encryptedImage = File(output, "ui/nested/icon.png")
            assertTrue(encryptedImage.isFile)
            assertTrue(
                AesFileEncryptor.hasMagic(
                    encryptedImage.readBytes(),
                    AesFileEncryptor.deriveAesKey(key)
                )
            )
            assertContentEquals(
                imageBytes,
                AesFileEncryptor.decrypt(
                    encryptedImage.readBytes(),
                    AesFileEncryptor.deriveAesKey(key),
                    "ui/nested/icon.png"
                )
            )
            assertContentEquals(imageBytes, image.readBytes())
            assertContentEquals(configBytes, File(output, "data/settings.properties").readBytes())
        } finally {
            root.deleteRecursively()
        }
    }
}
