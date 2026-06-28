import com.badlogic.gdx.Files
import com.badlogic.gdx.files.FileHandle
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.InputStreamReader
import java.io.Reader

/**
 * Wraps [Files] so every [FileHandle] returned for internal files is transparently decrypted.
 *
 * Security improvements over the XOR version:
 *  - AES-128-CTR encryption: known-plaintext does not recover the key
 *  - Per-file derived keys: one broken file does not expose other files
 *  - Random IV per file: identical assets produce different ciphertexts
 *  - Master key split across KEY_0..KEY_3 (four Ints): harder to locate
 *    in bytecode/memory than a single Long constant
 *
 * KEY_0..KEY_3 and ENABLED are patched to their real values by the
 * Cryptor Gradle Plugin at build time via ASM <clinit> prepend.
 * At compile time they remain 0 / false so dev builds are unaffected.
 */
class CryptorFilesWrapper(private val delegate: Files) : Files by delegate {

    companion object {
        // 16-byte AES master key split into four Ints.
        // Layout: KEY_0 = bytes 0-3 (MSB), KEY_3 = bytes 12-15 (LSB).
        // All four are patched atomically in <clinit> by EncryptClassesTask.
        @JvmField var KEY_0: Int = 0
        @JvmField var KEY_1: Int = 0
        @JvmField var KEY_2: Int = 0
        @JvmField var KEY_3: Int = 0
        @JvmField var ENABLED: Boolean = false

        private fun masterKey(): ByteArray =
            AesFileEncryptor.masterKeyFromInts(KEY_0, KEY_1, KEY_2, KEY_3)
    }

    override fun internal(path: String): FileHandle =
        if (ENABLED) CryptorFileHandle(delegate.internal(path)) else delegate.internal(path)

    // -------------------------------------------------------------------------
    // Inner FileHandle that AES-decrypts on read
    // -------------------------------------------------------------------------

    inner class CryptorFileHandle(private val source: FileHandle)
        : FileHandle(source.path(), source.type()) {

        private fun maybeDecrypt(raw: ByteArray): ByteArray =
            if (AesFileEncryptor.hasMagic(raw))
                AesFileEncryptor.decrypt(raw, masterKey(), normPath())
            else raw

        /** Normalized relative path — must match the path used at encryption time. */
        private fun normPath(): String = source.path().replace('\\', '/')

        override fun read(): InputStream = ByteArrayInputStream(maybeDecrypt(source.readBytes()))
        override fun readBytes(): ByteArray = maybeDecrypt(source.readBytes())
        override fun reader(): Reader = InputStreamReader(read(), Charsets.UTF_8)
        override fun reader(charset: String): Reader = InputStreamReader(read(), charset)

        override fun map(): java.nio.ByteBuffer {
            val data = readBytes()
            val buf = java.nio.ByteBuffer.allocateDirect(data.size)
            buf.put(data)
            buf.flip()
            return buf
        }

        override fun path(): String = source.path()
        override fun name(): String = source.name()
        override fun extension(): String = source.extension()
        override fun nameWithoutExtension(): String = source.nameWithoutExtension()
        override fun pathWithoutExtension(): String = source.pathWithoutExtension()
        override fun type(): Files.FileType = source.type()
        override fun exists(): Boolean = source.exists()
        override fun length(): Long {
            val raw = source.readBytes()
            return if (AesFileEncryptor.hasMagic(raw))
                (raw.size - AesFileEncryptor.HEADER_SIZE).toLong()
            else raw.size.toLong()
        }
        override fun lastModified(): Long = source.lastModified()
        override fun isDirectory(): Boolean = source.isDirectory

        override fun child(name: String): FileHandle = CryptorFileHandle(source.child(name))
        override fun sibling(name: String): FileHandle = CryptorFileHandle(source.sibling(name))
        override fun parent(): FileHandle = CryptorFileHandle(source.parent())

        override fun list(): Array<FileHandle> = source.list().map { CryptorFileHandle(it) }.toTypedArray()
        override fun list(suffix: String): Array<FileHandle> = source.list(suffix).map { CryptorFileHandle(it) }.toTypedArray()
        override fun file(): java.io.File = source.file()
    }
}
