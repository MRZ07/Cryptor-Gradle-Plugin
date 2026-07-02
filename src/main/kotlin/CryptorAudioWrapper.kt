import com.badlogic.gdx.Audio
import com.badlogic.gdx.Gdx
import com.badlogic.gdx.audio.Music
import com.badlogic.gdx.audio.Sound
import com.badlogic.gdx.files.FileHandle
import com.badlogic.gdx.utils.GdxRuntimeException
import java.io.File
import java.io.FileOutputStream
import java.util.concurrent.ConcurrentHashMap

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
 *  2. Writing them to a file inside the app's internal files directory
 *     (<pkg>/files/cryptor_audio/), which the OS never auto-cleans.
 *  3. Passing [Gdx.files.absolute] of that file to the delegate — on Android,
 *     [com.badlogic.gdx.backends.android.AndroidFiles.absolute] returns an
 *     [com.badlogic.gdx.backends.android.AndroidFileHandle] with [FileType.Absolute],
 *     so the cast succeeds and the audio backend takes the file-path branch (no
 *     AssetManager involvement needed).
 *
 * Files are cached by source path so the same audio file is only decrypted and
 * written once per session. A path-derived filename (rather than a random one) means
 * the same asset always maps to the same file on disk, preventing stale-file
 * accumulation across app restarts. The file is fsynced before handing its path to
 * the audio backend, which prevents [MediaPlayer.setDataSourceFD] from reading a
 * partially-flushed file on devices with aggressive OS-level write caching.
 *
 * [ENABLED] is patched at build time by the Cryptor Gradle Plugin (same mechanism
 * used for [CryptorFilesWrapper]) — identical to how StringDecryptor is patched.
 */
class CryptorAudioWrapper(private val delegate: Audio) : Audio by delegate {

    companion object {
        @JvmField var ENABLED: Boolean = false

        /** Decrypted audio files keyed by their source path, reused across calls. */
        private val cache = ConcurrentHashMap<String, File>()
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

        val ext = fileHandle.extension().ifEmpty { "tmp" }
        // Write to the internal files directory, NOT the system temp / cache directory.
        // On Android, java.io.tmpdir resolves to <pkg>/cache/ which the OS is allowed to
        // clean up under storage pressure — even while the app is running. The sibling
        // <pkg>/files/ directory is never auto-cleaned by the OS.
        // We derive the files dir from the system temp dir: on Android, tmpdir is always
        // <pkg>/cache, so resolveSibling("files") gives the safe <pkg>/files directory.
        val tmpDir = File(System.getProperty("java.io.tmpdir", "."))
        val baseDir = if (tmpDir.name == "cache" && tmpDir.parentFile != null)
            tmpDir.resolveSibling("files")
        else
            tmpDir
        val audioDir = File(baseDir, "cryptor_audio")
        audioDir.mkdirs()

        // Use a path-derived filename so the same asset always maps to the same file on
        // disk. This prevents stale file accumulation across app restarts (no random
        // suffix, no deleteOnExit needed) and keeps the on-disk state deterministic.
        val safePath = path.replace('/', '_').replace('\\', '_')
        val file = File(audioDir, "cryptor_${safePath}")

        // Write with an explicit fsync so the bytes are durably on disk before
        // MediaPlayer opens the file descriptor. Without this, some Android devices
        // report "setDataSourceFD failed: status=0x80000000" because the OS
        // write-back cache has not yet committed the data.
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
