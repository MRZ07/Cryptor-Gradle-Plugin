import com.badlogic.gdx.Files
import com.badlogic.gdx.files.FileHandle
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.InputStreamReader
import java.io.Reader

/**
 * Wraps [Files] so every [FileHandle] returned for internal files is transparently decrypted.
 *
 * [KEY] and [ENABLED] are patched to their real values by the Cryptor Gradle Plugin at
 * build time via ASM <clinit> prepend — identical to how StringDecryptor is patched.
 * At compile time both remain at their default (passthrough) values so dev builds are unaffected.
 */
class CryptorFilesWrapper(private val delegate: Files) : Files by delegate {

    companion object {
        @JvmField var KEY: Long = 0L
        @JvmField var ENABLED: Boolean = false
    }

    override fun internal(path: String): FileHandle =
        if (ENABLED) CryptorFileHandle(delegate.internal(path)) else delegate.internal(path)

    // -------------------------------------------------------------------------
    // Inner FileHandle that decrypts on read
    // -------------------------------------------------------------------------

    inner class CryptorFileHandle(private val source: FileHandle)
        : FileHandle(source.path(), source.type()) {

        /** XOR is its own inverse — same operation encrypts and decrypts. */
        private fun xorDecrypt(bytes: ByteArray): ByteArray {
            val key = KEY
            return ByteArray(bytes.size) { i ->
                val keyByte = ((key shr ((i % 8) * 8)) and 0xFF).toInt()
                (bytes[i].toInt() xor keyByte).toByte()
            }
        }

        /**
         * Returns decrypted bytes if [raw] starts with the magic header written by
         * EncryptAssetsTask, otherwise returns [raw] unchanged (file was not encrypted).
         */
        private fun maybeDecrypt(raw: ByteArray): ByteArray {
            return if (raw.size >= 4
                && raw[0] == 0xC0.toByte()
                && raw[1] == 0xDE.toByte()
                && raw[2] == 0xBA.toByte()
                && raw[3] == 0xBE.toByte()
            ) {
                xorDecrypt(raw.copyOfRange(4, raw.size))
            } else {
                raw
            }
        }

        override fun read(): InputStream = ByteArrayInputStream(maybeDecrypt(source.readBytes()))

        override fun readBytes(): ByteArray = maybeDecrypt(source.readBytes())

        override fun reader(): Reader = InputStreamReader(read(), Charsets.UTF_8)

        override fun reader(charset: String): Reader = InputStreamReader(read(), charset)

        // FreeTypeFontGenerator calls font.map() to memory-map files for FreeType.
        // Without overriding map(), it falls through to the raw source and returns a
        // MappedByteBuffer of the ENCRYPTED bytes, while length() correctly reports
        // the decrypted size — causing a "newLimit > capacity" crash in BufferUtils.copy().
        // Fix: return a direct ByteBuffer of the decrypted content.
        override fun map(): java.nio.ByteBuffer {
            val data = readBytes()
            val buf = java.nio.ByteBuffer.allocateDirect(data.size)
            buf.put(data)
            buf.flip()
            return buf
        }

        // Path delegation — keep navigation in the encrypted file tree
        override fun path(): String = source.path()
        override fun name(): String = source.name()
        override fun extension(): String = source.extension()
        override fun nameWithoutExtension(): String = source.nameWithoutExtension()
        override fun pathWithoutExtension(): String = source.pathWithoutExtension()
        override fun type(): Files.FileType = source.type()
        override fun exists(): Boolean = source.exists()
        override fun length(): Long {
            // Derive length from actual decrypted content — this is always correct
            // regardless of whether the file is encrypted or not, and stays consistent
            // with readBytes() and map(). The naive "raw - 4" approach breaks for
            // files that are not encrypted (e.g. if encryptAssets was off for a variant).
            return readBytes().size.toLong()
        }
        override fun lastModified(): Long = source.lastModified()
        override fun isDirectory(): Boolean = source.isDirectory

        // Wrap navigated handles so they are also decrypted
        override fun child(name: String): FileHandle = CryptorFileHandle(source.child(name))
        override fun sibling(name: String): FileHandle = CryptorFileHandle(source.sibling(name))
        override fun parent(): FileHandle = CryptorFileHandle(source.parent())

        override fun list(): Array<FileHandle> = source.list().map { CryptorFileHandle(it) }.toTypedArray()
        override fun list(suffix: String): Array<FileHandle> = source.list(suffix).map { CryptorFileHandle(it) }.toTypedArray()

        override fun file(): java.io.File = source.file()
    }
}
