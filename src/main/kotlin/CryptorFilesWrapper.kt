import com.badlogic.gdx.Files
import com.badlogic.gdx.files.FileHandle
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.InputStreamReader
import java.io.Reader

/**
 * Wraps [Files] so every internal [FileHandle] is transparently AES-decrypted.
 *
 * KEY_0..KEY_3 and ENABLED are patched by the Cryptor Gradle Plugin via ASM at build time.
 * The four Int fields reconstruct a 16-byte AES master key; they are injected as results
 * of an XOR between two unrelated-looking constants (arithmetic veil) — see EncryptClassesTask.
 */
class CryptorFilesWrapper(private val delegate: Files) : Files by delegate {

    companion object {
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

    inner class CryptorFileHandle(private val source: FileHandle)
        : FileHandle(source.path(), source.type()) {

        private fun normPath(): String = source.path().replace('\\', '/')

        private fun maybeDecrypt(raw: ByteArray): ByteArray {
            val mk = masterKey()
            return if (AesFileEncryptor.hasMagic(raw, mk))
                AesFileEncryptor.decrypt(raw, mk, normPath())
            else raw
        }

        override fun read(): InputStream  = ByteArrayInputStream(maybeDecrypt(source.readBytes()))
        override fun readBytes(): ByteArray = maybeDecrypt(source.readBytes())
        override fun reader(): Reader = InputStreamReader(read(), Charsets.UTF_8)
        override fun reader(charset: String): Reader = InputStreamReader(read(), charset)

        override fun map(): java.nio.ByteBuffer {
            val data = readBytes()
            val buf  = java.nio.ByteBuffer.allocateDirect(data.size)
            buf.put(data); buf.flip()
            return buf
        }

        override fun length(): Long {
            val raw = source.readBytes()
            return if (AesFileEncryptor.hasMagic(raw, masterKey()))
                (raw.size - AesFileEncryptor.HEADER_SIZE).toLong()
            else raw.size.toLong()
        }

        override fun path(): String  = source.path()
        override fun name(): String  = source.name()
        override fun extension(): String  = source.extension()
        override fun nameWithoutExtension(): String = source.nameWithoutExtension()
        override fun pathWithoutExtension(): String = source.pathWithoutExtension()
        override fun type(): Files.FileType = source.type()
        override fun exists(): Boolean  = source.exists()
        override fun lastModified(): Long = source.lastModified()
        override fun isDirectory(): Boolean = source.isDirectory

        override fun child(name: String): FileHandle  = CryptorFileHandle(source.child(name))
        override fun sibling(name: String): FileHandle = CryptorFileHandle(source.sibling(name))
        override fun parent(): FileHandle  = CryptorFileHandle(source.parent())

        override fun list(): Array<FileHandle> = source.list().map { CryptorFileHandle(it) }.toTypedArray()
        override fun list(suffix: String): Array<FileHandle> = source.list(suffix).map { CryptorFileHandle(it) }.toTypedArray()
        override fun file(): java.io.File = source.file()
    }
}
