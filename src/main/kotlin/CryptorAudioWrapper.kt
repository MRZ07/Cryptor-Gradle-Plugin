import com.badlogic.gdx.Audio
import com.badlogic.gdx.Gdx
import com.badlogic.gdx.audio.Music
import com.badlogic.gdx.audio.Sound
import com.badlogic.gdx.files.FileHandle
import com.badlogic.gdx.utils.GdxRuntimeException
import java.io.File
import java.io.FileOutputStream
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Wraps [Audio] so that [newSound] and [newMusic] work correctly when the
 * [FileHandle] originates from [CryptorFilesWrapper].
 *
 * On Android, [com.badlogic.gdx.backends.android.DefaultAndroidAudio] unconditionally
 * casts every [FileHandle] to [com.badlogic.gdx.backends.android.AndroidFileHandle].
 * [CryptorFilesWrapper.CryptorFileHandle] extends plain [FileHandle], so that cast
 * throws a [ClassCastException] at runtime.
 *
 * This wrapper sidesteps the cast by:
 *  1. Reading the already-decrypted bytes from the handle via [FileHandle.readBytes].
 *  2. Writing them to a file inside the app's internal files directory under a
 *     version-keyed subdirectory (<pkg>/files/cryptor_audio/<keyHash>/).
 *     The key hash (first 4 bytes of SHA-256 of the master key, hex-encoded) makes
 *     the directory unique per encryption key — on key rotation or version change
 *     the old directory is cleaned up automatically on first launch.
 *  3. Passing [Gdx.files.absolute] of that file to the delegate — on Android,
 *     [com.badlogic.gdx.backends.android.AndroidFiles.absolute] returns an
 *     [com.badlogic.gdx.backends.android.AndroidFileHandle] with [FileType.Absolute],
 *     so the cast succeeds and the audio backend takes the file-path branch.
 *
 * Files are cached by source path so the same audio file is only decrypted and
 * written once per session. The file is fsynced before handing its path to
 * the audio backend to prevent partial-flush issues on some Android devices.
 *
 * [ENABLED] is patched at build time by the Cryptor Gradle Plugin.
 */
class CryptorAudioWrapper(private val delegate: Audio) : Audio by delegate {

    companion object {
        @JvmField var ENABLED: Boolean = false

        /** Decrypted audio files keyed by their source path, reused across calls. */
        private val cache = ConcurrentHashMap<String, File>()

        /** Guards the one-time stale-directory cleanup. */
        private val cleanupDone = AtomicBoolean(false)

        /**
         * Hex-encoded first 4 bytes of SHA-256(masterKey).
         * This matches [AesFileEncryptor.deriveMagic] so any change to the encryption
         * key produces a different hash and triggers cleanup of the old audio directory.
         */
        private fun keyHash(): String {
            val mk    = CryptorFilesWrapper.masterKey()
            val magic = AesFileEncryptor.deriveMagic(mk)
            return magic.joinToString("") { "%02x".format(it) }
        }

        /**
         * Returns the versioned audio cache directory, cleaning up sibling directories
         * from previous encryption keys on first call.
         */
        private fun resolveAudioDir(): File {
            val tmpDir  = File(System.getProperty("java.io.tmpdir", "."))
            val baseDir = if (tmpDir.name == "cache" && tmpDir.parentFile != null)
                tmpDir.resolveSibling("files")
            else
                tmpDir

            val parentDir  = File(baseDir, "cryptor_audio")
            val currentDir = File(parentDir, keyHash())

            // Delete sibling directories that belong to a previous key — runs at most once.
            if (cleanupDone.compareAndSet(false, true) && parentDir.exists()) {
                parentDir.listFiles()?.forEach { sibling ->
                    if (sibling.isDirectory && sibling.name != currentDir.name) {
                        sibling.deleteRecursively()
                    }
                }
            }

            currentDir.mkdirs()
            return currentDir
        }
    }

    override fun newSound(fileHandle: FileHandle): Sound =
        delegate.newSound(if (ENABLED) toAbsoluteTempHandle(fileHandle) else fileHandle)

    override fun newMusic(fileHandle: FileHandle): Music =
        delegate.newMusic(if (ENABLED) toAbsoluteTempHandle(fileHandle) else fileHandle)

    /**
     * Returns an absolute [FileHandle] pointing to the decrypted audio bytes.
     *
     * The result is cached by [fileHandle] path so repeated calls (e.g. replaying the
     * same music track) skip decryption and the write entirely.
     * The file is written with an explicit fsync so [MediaPlayer] always sees complete,
     * valid bytes even on devices that delay flushing write buffers to disk.
     */
    private fun toAbsoluteTempHandle(fileHandle: FileHandle): FileHandle {
        val path = fileHandle.path()

        // Return cached file if it still exists and has a non-zero size.
        val cached = cache[path]
        if (cached != null && cached.exists() && cached.length() > 0L) {
            return Gdx.files.absolute(cached.absolutePath)
        }

        val bytes = fileHandle.readBytes()  // CryptorFileHandle.readBytes() already decrypts
        if (bytes.isEmpty()) {
            throw GdxRuntimeException(
                "Decrypted audio file is empty (decryption may have failed): $path"
            )
        }

        val audioDir = resolveAudioDir()
        val safePath = path.replace('/', '_').replace('\\', '_')
        val file     = File(audioDir, "cryptor_${safePath}")

        // Write with an explicit fsync so the bytes are durably on disk before
        // MediaPlayer opens the file descriptor.
        FileOutputStream(file).use { fos ->
            fos.write(bytes)
            fos.flush()
            fos.fd.sync()
        }

        if (file.length() != bytes.size.toLong()) {
            file.delete()
            throw GdxRuntimeException(
                "Audio file size mismatch for $path " +
                "(expected ${bytes.size}, got ${file.length()})"
            )
        }

        cache[path] = file
        return Gdx.files.absolute(file.absolutePath)
    }
}
