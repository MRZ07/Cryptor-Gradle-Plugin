import com.badlogic.gdx.Audio
import com.badlogic.gdx.Gdx
import com.badlogic.gdx.audio.Music
import com.badlogic.gdx.audio.Sound
import com.badlogic.gdx.files.FileHandle
import com.badlogic.gdx.utils.GdxRuntimeException
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Wraps [Audio] so that [newSound] and [newMusic] work correctly when the
 * [FileHandle] originates from [CryptorFilesWrapper].
 *
 * ENABLED has been removed. The wrapper is always active when injected.
 * Non-encrypted audio files (CryptorFilesWrapper returns raw bytes when hasMagic=false)
 * are written to disk and played normally — no functional difference.
 *
 * Audio files are cached in a version-keyed directory so stale files from old
 * encryption keys are cleaned up automatically on first launch.
 */
class CryptorAudioWrapper(private val delegate: Audio) : Audio by delegate {

    companion object {
        private val cache = ConcurrentHashMap<String, File>()
        private val cleanupDone = AtomicBoolean(false)

        private fun keyHash(): String {
            val magic = AesFileEncryptor.deriveMagic(CryptorFilesWrapper.masterKey())
            return magic.joinToString("") { "%02x".format(it) }
        }

        private fun resolveAudioDir(): File {
            val tmpDir  = File(System.getProperty("java.io.tmpdir", "."))
            val baseDir = if (tmpDir.name == "cache" && tmpDir.parentFile != null)
                tmpDir.resolveSibling("files") else tmpDir
            val parentDir  = File(baseDir, "cryptor_audio")
            val currentDir = File(parentDir, keyHash())
            if (cleanupDone.compareAndSet(false, true) && parentDir.exists()) {
                parentDir.listFiles()?.forEach { sibling ->
                    if (sibling.isDirectory && sibling.name != currentDir.name)
                        sibling.deleteRecursively()
                }
            }
            currentDir.mkdirs()
            return currentDir
        }

        internal fun buildCacheFileName(path: String): String {
            val normalized = path.replace('\\', '/')
            val digest = MessageDigest
                .getInstance("SHA-256")
                .digest(normalized.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }
            val ext = normalized.substringAfterLast('.', "")
                .takeIf { it.isNotEmpty() && !it.contains('/') }
                ?.let { ".${it.lowercase()}" }
                ?: ""
            return "cryptor_${digest}${ext}"
        }
    }

    override fun newSound(fileHandle: FileHandle): Sound =
        delegate.newSound(toAbsoluteTempHandle(fileHandle))

    override fun newMusic(fileHandle: FileHandle): Music =
        delegate.newMusic(toAbsoluteTempHandle(fileHandle))

    private fun toAbsoluteTempHandle(fileHandle: FileHandle): FileHandle {
        val path   = fileHandle.path()
        val cached = cache[path]
        if (cached != null && cached.exists() && cached.length() > 0L)
            return Gdx.files.absolute(cached.absolutePath)

        val bytes = fileHandle.readBytes()
        if (bytes.isEmpty())
            throw GdxRuntimeException("Decrypted audio file is empty: $path")

        val audioDir = resolveAudioDir()
        val file     = File(audioDir, buildCacheFileName(path))

        FileOutputStream(file).use { fos -> fos.write(bytes); fos.flush(); fos.fd.sync() }

        if (file.length() != bytes.size.toLong()) {
            file.delete()
            throw GdxRuntimeException(
                "Audio size mismatch for $path (expected ${bytes.size}, got ${file.length()})")
        }

        cache[path] = file
        return Gdx.files.absolute(file.absolutePath)
    }
}
