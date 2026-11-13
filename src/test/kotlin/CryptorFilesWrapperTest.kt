import com.badlogic.gdx.Application
import com.badlogic.gdx.Audio
import com.badlogic.gdx.Files
import com.badlogic.gdx.Gdx
import com.badlogic.gdx.audio.Music
import com.badlogic.gdx.audio.Sound
import com.badlogic.gdx.files.FileHandle
import java.io.ByteArrayInputStream
import java.io.File
import java.io.InputStream
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue

class CryptorFilesWrapperTest {

    @Test
    fun encryptedInternalFileAndAudioUseWritableIosLocalFiles() {
        val root = tempRoot("cryptor-ios-wrapper")
        val previousFiles = Gdx.files
        val previousApp = Gdx.app
        val plainBytes = byteArrayOf(11, 22, 33, 44, 55)
        val masterKey = ByteArray(16)
        val assetPath = "images/${System.nanoTime()}.png"
        val tmxPath = "map/level/${System.nanoTime()}.tmx"
        val audioPath = "sounds/${System.nanoTime()}.mp3"
        val musicPath = "music/${System.nanoTime()}.mp3"
        var receivedSoundFile: FileHandle? = null
        var receivedMusicFile: FileHandle? = null
        val sound = proxy<Sound>(Sound::class.java) { _, _ -> null }
        val music = proxy<Music>(Music::class.java) { _, _ -> null }
        val audio = proxy<Audio>(Audio::class.java) { method, args ->
            when (method.name) {
                "newSound" -> {
                    receivedSoundFile = args!![0] as FileHandle
                    sound
                }
                "newMusic" -> {
                    receivedMusicFile = args!![0] as FileHandle
                    music
                }
                else -> null
            }
        }
        val tmxBytes = "<map version=\"1.0\"/>".toByteArray(Charsets.UTF_8)
        val encryptedAssets = mapOf(
            assetPath to AesFileEncryptor.encrypt(plainBytes, masterKey, assetPath),
            tmxPath to AesFileEncryptor.encrypt(tmxBytes, masterKey, tmxPath),
            audioPath to AesFileEncryptor.encrypt(plainBytes, masterKey, audioPath),
            musicPath to AesFileEncryptor.encrypt(plainBytes, masterKey, musicPath)
        )
        val sourceFiles = mutableMapOf<String, MemoryInternalFileHandle>()
        val files = proxy<Files>(Files::class.java) { method, args ->
            when (method.name) {
                "internal" -> sourceFiles.getOrPut(args!![0] as String) {
                    MemoryInternalFileHandle(
                        args[0] as String,
                        encryptedAssets.getValue(args[0] as String),
                        File(root, "bundle/${args[0]}")
                    )
                }
                "local" -> FileHandle(File(root, args!![0] as String))
                "absolute" -> FileHandle(File(args!![0] as String))
                else -> throw UnsupportedOperationException("Unexpected Files call: ${method.name}")
            }
        }

        try {
            root.mkdirs()
            Gdx.files = files
            Gdx.app = application(Application.ApplicationType.iOS)

            val wrappedFiles = CryptorFilesWrapper(files)
            val fileHandle = wrappedFiles.internal(assetPath)
            assertContentEquals(plainBytes, fileHandle.readBytes())
            val decryptedFile = fileHandle.file()
            assertTrue(decryptedFile.absolutePath.startsWith(root.absolutePath))
            assertContentEquals(plainBytes, decryptedFile.readBytes())
            assertTrue(sourceFiles.getValue(assetPath).readCount > 0)
            assertContentEquals(tmxBytes, wrappedFiles.internal(tmxPath).readBytes())

            val audioWrapper = CryptorAudioWrapper(audio)
            audioWrapper.newSound(wrappedFiles.internal(audioPath))
            val audioFile = requireNotNull(receivedSoundFile).file()
            assertTrue(audioFile.absolutePath.startsWith(root.absolutePath))
            assertContentEquals(plainBytes, audioFile.readBytes())

            audioWrapper.newMusic(wrappedFiles.internal(musicPath))
            val musicFile = requireNotNull(receivedMusicFile).file()
            assertTrue(musicFile.absolutePath.startsWith(root.absolutePath))
            assertContentEquals(plainBytes, musicFile.readBytes())
        } finally {
            Gdx.files = previousFiles
            Gdx.app = previousApp
            root.deleteRecursively()
        }
    }

    @Test
    fun nonIosFileReturnsDelegatePathWithoutReadingAssetBytes() {
        val root = tempRoot("cryptor-non-ios-wrapper")
        val previousApp = Gdx.app
        val backingFile = File(root, "internal/sprite.png")
        val source = MemoryInternalFileHandle("sprite.png", byteArrayOf(1, 2, 3), backingFile)
        val files = proxy<Files>(Files::class.java) { method, _ ->
            if (method.name == "internal") source else null
        }

        try {
            Gdx.app = application(Application.ApplicationType.Android)
            val result = CryptorFilesWrapper(files).internal("sprite.png").file()

            assertSame(backingFile, result)
            assertEquals(0, source.readCount)
        } finally {
            Gdx.app = previousApp
            root.deleteRecursively()
        }
    }

    private fun tempRoot(prefix: String): File = File(
        System.getProperty("java.io.tmpdir"),
        "$prefix-${System.nanoTime()}"
    )

    private fun application(type: Application.ApplicationType): Application =
        proxy(Application::class.java) { method, _ ->
            if (method.name == "getType") type else defaultValue(method.returnType)
        }

    @Suppress("UNCHECKED_CAST")
    private fun <T> proxy(
        type: Class<T>,
        handler: (java.lang.reflect.Method, Array<out Any?>?) -> Any?
    ): T = Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, method, args ->
        handler(method, args)
    } as T

    private fun defaultValue(type: Class<*>): Any? = when (type) {
        java.lang.Boolean.TYPE -> false
        java.lang.Integer.TYPE -> 0
        java.lang.Long.TYPE -> 0L
        java.lang.Float.TYPE -> 0f
        java.lang.Double.TYPE -> 0.0
        java.lang.Short.TYPE -> 0.toShort()
        java.lang.Byte.TYPE -> 0.toByte()
        java.lang.Character.TYPE -> 0.toChar()
        else -> null
    }

    private class MemoryInternalFileHandle(
        private val assetPath: String,
        private val bytes: ByteArray,
        private val backingFile: File
    ) : FileHandle(assetPath, Files.FileType.Internal) {
        var readCount = 0

        override fun path(): String = assetPath
        override fun read(): InputStream {
            readCount++
            return ByteArrayInputStream(bytes)
        }
        override fun readBytes(): ByteArray {
            readCount++
            return bytes.copyOf()
        }
        override fun exists(): Boolean = true
        override fun file(): File = backingFile
    }
}
