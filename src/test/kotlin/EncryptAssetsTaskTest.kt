import java.io.File
import org.gradle.api.GradleException
import org.gradle.testfixtures.ProjectBuilder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
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

    @Test
    fun sharedAssetHelperRejectsStaleHeaderAndRoundTripsCurrentOutput() {
        val root = File(
            System.getProperty("java.io.tmpdir"),
            "cryptor-shared-asset-test-${System.nanoTime()}"
        )
        val masterKey = AesFileEncryptor.deriveAesKey(0x76543210ABCDEFL)
        val stale = AesFileEncryptor.deriveMagic(masterKey) + ByteArray(AesFileEncryptor.IV_SIZE)
        val staleDest = File(root, "stale/asset.png")
        val relPath = "images/icon.png"
        val plain = "shared helper output".toByteArray(Charsets.UTF_8)
        val encryptedDest = File(root, relPath)

        try {
            staleDest.parentFile.mkdirs()
            assertFailsWith<GradleException> {
                EncryptAssetsTask.encryptAsset(stale, staleDest, "stale/asset.png", masterKey)
            }
            assertTrue(!staleDest.exists())

            encryptedDest.parentFile.mkdirs()
            EncryptAssetsTask.encryptAsset(plain, encryptedDest, relPath, masterKey)
            val encrypted = encryptedDest.readBytes()
            assertTrue(AesFileEncryptor.hasMagicPrefix(encrypted, masterKey))
            assertTrue(AesFileEncryptor.isWellFormed(encrypted))
            assertContentEquals(plain, AesFileEncryptor.decrypt(encrypted, masterKey, relPath))
        } finally {
            root.deleteRecursively()
        }
    }
}
