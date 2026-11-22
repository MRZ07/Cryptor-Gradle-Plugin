import com.badlogic.gdx.Audio
import com.badlogic.gdx.Files
import com.badlogic.gdx.Gdx
import com.badlogic.gdx.audio.Music
import com.badlogic.gdx.files.FileHandle
import com.badlogic.gdx.utils.GdxRuntimeException
import java.io.File
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class CryptorAudioWrapperTest {

    @Test
    fun cacheFileName_staysShort_forVeryLongAssetPath() {
        val longPath = buildString {
            append("sounds/")
            repeat(32) { idx ->
                append("screen_section_")
                append(idx)
                append('_')
                append("very_long_descriptor")
                append('/')
            }
            append("title/start.mp3")
        }

        val fileName = CryptorAudioWrapper.buildCacheFileName(longPath)

        assertTrue(fileName.length <= 120, "filename too long: ${fileName.length}")
        assertTrue(fileName.endsWith(".mp3"), "extension must be preserved")
    }

    @Test
    fun cacheFileName_isDeterministic_andDiffersByPath() {
        val pathA = "sounds/ui/screen/title/start.mp3"
        val pathB = "sounds/ui/screen/title/end.mp3"

        val nameA1 = CryptorAudioWrapper.buildCacheFileName(pathA)
        val nameA2 = CryptorAudioWrapper.buildCacheFileName(pathA)
        val nameB = CryptorAudioWrapper.buildCacheFileName(pathB)

        assertEquals(nameA1, nameA2)
        assertNotEquals(nameA1, nameB)
    }

    @Test
    fun materialize_usesTheWritableLibGdxLocalArea() {
        val root = File(
            System.getProperty("java.io.tmpdir"),
            "cryptor-local-test-${System.nanoTime()}"
        )
        val previousFiles = Gdx.files
        val localFiles = Proxy.newProxyInstance(
            Files::class.java.classLoader,
            arrayOf(Files::class.java)
        ) { _, method, args ->
            when (method.name) {
                "local" -> FileHandle(File(root, args!![0] as String))
                "absolute" -> FileHandle(File(args!![0] as String))
                "internal" -> FileHandle(File(root, args!![0] as String))
                else -> throw UnsupportedOperationException("Unexpected Files call: ${method.name}")
            }
        } as Files
        val expectedBytes = byteArrayOf(5, 4, 3, 2, 1)

        try {
            root.mkdirs()
            Gdx.files = localFiles
            val cached = CryptorAudioWrapper.materialize(
                "assets",
                "levels/intro/background.png",
                expectedBytes
            )

            assertTrue(cached.file().absolutePath.startsWith(root.absolutePath))
            assertContentEquals(expectedBytes, cached.readBytes())
        } finally {
            Gdx.files = previousFiles
            root.deleteRecursively()
        }
    }

    @Test
    fun newMusic_rebuildsTheCopyOnceWhenTheBackendRejectsIt() {
        val root = File(
            System.getProperty("java.io.tmpdir"),
            "cryptor-audio-retry-${System.nanoTime()}"
        )
        val previousFiles = Gdx.files
        val previousApp = Gdx.app
        val plainBytes = byteArrayOf(7, 7, 7, 7)
        val track = File(root, "music/track.mp3")
        var attempts = 0
        val publishedPaths = mutableListOf<String>()
        val music = proxyOf(Music::class.java)
        val audio = Proxy.newProxyInstance(
            Audio::class.java.classLoader,
            arrayOf(Audio::class.java)
        ) { _, method, args ->
            when (method.name) {
                "newMusic" -> {
                    attempts++
                    val handle = args!![0] as FileHandle
                    publishedPaths += handle.path()
                    if (attempts == 1) throw GdxRuntimeException("Error loading audio file: ${handle.path()}")
                    music
                }
                else -> throw UnsupportedOperationException("Unexpected Audio call: ${method.name}")
            }
        } as Audio
        val files = Proxy.newProxyInstance(
            Files::class.java.classLoader,
            arrayOf(Files::class.java)
        ) { _, method, args ->
            when (method.name) {
                "absolute" -> FileHandle(File(args!![0] as String))
                "local" -> FileHandle(File(root, args!![0] as String))
                else -> throw UnsupportedOperationException("Unexpected Files call: ${method.name}")
            }
        } as Files

        try {
            root.mkdirs()
            track.parentFile.mkdirs()
            track.writeBytes(plainBytes)
            Gdx.files = files
            Gdx.app = null

            CryptorAudioWrapper(audio).newMusic(FileHandle(track))

            assertEquals(2, attempts, "a rejected copy must be rebuilt and retried once")
            assertEquals(publishedPaths[0], publishedPaths[1], "the retry must target the same published file")
            val published = File(publishedPaths[1])
            assertTrue(published.isFile, "the retried copy must exist")
            assertContentEquals(plainBytes, published.readBytes())
            assertFalse(
                File(published.parentFile, published.name + ".part").exists(),
                "no partial file may be left behind"
            )
        } finally {
            Gdx.files = previousFiles
            Gdx.app = previousApp
            root.deleteRecursively()
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> proxyOf(type: Class<T>): T =
        Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, _, _ -> null } as T
}
