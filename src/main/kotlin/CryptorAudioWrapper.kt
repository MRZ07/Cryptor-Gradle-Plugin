import com.badlogic.gdx.Audio
import com.badlogic.gdx.Gdx
import com.badlogic.gdx.audio.Music
import com.badlogic.gdx.audio.Sound
import com.badlogic.gdx.files.FileHandle
import java.io.File

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
 *  2. Writing them to a temp file on the device's external storage.
 *  3. Passing [Gdx.files.absolute] of that temp file to the delegate — on Android,
 *     [com.badlogic.gdx.backends.android.AndroidFiles.absolute] returns an
 *     [com.badlogic.gdx.backends.android.AndroidFileHandle] with [FileType.Absolute],
 *     so the cast succeeds and the audio backend takes the file-path branch (no
 *     AssetManager involvement needed).
 *
 * [KEY] and [ENABLED] are patched at build time by the Cryptor Gradle Plugin (same
 * mechanism used for [CryptorFilesWrapper]) — identical to how StringDecryptor is patched.
 */
class CryptorAudioWrapper(private val delegate: Audio) : Audio by delegate {

    companion object {
        @JvmField var ENABLED: Boolean = false
    }

    override fun newSound(fileHandle: FileHandle): Sound =
        delegate.newSound(if (ENABLED) toAbsoluteTempHandle(fileHandle) else fileHandle)

    override fun newMusic(fileHandle: FileHandle): Music =
        delegate.newMusic(if (ENABLED) toAbsoluteTempHandle(fileHandle) else fileHandle)

    /**
     * Writes the (already decrypted) bytes from [fileHandle] to a temp file and
     * returns an absolute [FileHandle] pointing to it.
     *
     * On Android, [Gdx.files.absolute] returns an AndroidFileHandle, which satisfies
     * the cast in DefaultAndroidAudio without any Android-specific code here.
     * The file type is Absolute (not Internal), so DefaultAndroidAudio falls back to
     * [soundPool.load(file().getPath(), 1)] instead of the AssetManager path.
     */
    private fun toAbsoluteTempHandle(fileHandle: FileHandle): FileHandle {
        val ext = fileHandle.extension().ifEmpty { "tmp" }
        val temp = File.createTempFile("cryptor_", ".$ext")
        temp.deleteOnExit()
        temp.writeBytes(fileHandle.readBytes())  // CryptorFileHandle.readBytes() already decrypts
        return Gdx.files.absolute(temp.absolutePath)
    }
}
