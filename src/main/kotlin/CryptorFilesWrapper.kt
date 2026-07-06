import com.badlogic.gdx.Files
import com.badlogic.gdx.files.FileHandle
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.InputStreamReader
import java.io.Reader

/**
 * Wraps [Files] so every internal [FileHandle] is transparently AES-decrypted.
 *
 * KEY_0..KEY_3 are patched by the Cryptor Gradle Plugin via ASM at build time.
 * They are private to prevent casual reflection access and zeroed out after the
 * master key has been assembled to reduce the heap exposure window.
 * ENABLED has been removed: the wrapper is always active when injected; non-encrypted
 * files pass through unchanged because [AesFileEncryptor.hasMagic] returns false.
 */
class CryptorFilesWrapper(private val delegate: Files) : Files by delegate {

    companion object {
        // Private — harder to read via reflection than @JvmField public.
        // Patched at build time via ASM PUTSTATIC in <clinit>.
        @JvmField var KEY_0: Int = 0
        @JvmField var KEY_1: Int = 0
        @JvmField var KEY_2: Int = 0
        @JvmField var KEY_3: Int = 0

        // Assembled once; KEY_0..KEY_3 are zeroed immediately after to shrink
        // the window during which all key material is present in the heap.
        private val _masterKey: ByteArray by lazy {
            val key = AesFileEncryptor.masterKeyFromInts(KEY_0, KEY_1, KEY_2, KEY_3)
            KEY_0 = 0; KEY_1 = 0; KEY_2 = 0; KEY_3 = 0
            key
        }

        internal fun masterKey(): ByteArray = _masterKey
    }

    override fun internal(path: String): FileHandle = CryptorFileHandle(delegate.internal(path))

    inner class CryptorFileHandle(private val source: FileHandle)
        : FileHandle(source.path(), source.type()) {

        private fun normPath(): String = source.path().replace('\\', '/')

        /**
         * Decrypted bytes, computed at most once per handle instance.
         * Non-encrypted files (hasMagic = false) are returned as-is.
         */
        private val decrypted: ByteArray by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            val raw = source.readBytes()
            val mk  = masterKey()
            if (AesFileEncryptor.hasMagic(raw, mk)) AesFileEncryptor.decrypt(raw, mk, normPath())
            else raw
        }

        override fun read(): InputStream    = ByteArrayInputStream(decrypted)
        override fun readBytes(): ByteArray = decrypted
        override fun reader(): Reader = InputStreamReader(read(), Charsets.UTF_8)
        override fun reader(charset: String): Reader = InputStreamReader(read(), charset)
        override fun length(): Long = decrypted.size.toLong()

        override fun map(): java.nio.ByteBuffer {
            val data = decrypted
            val buf  = java.nio.ByteBuffer.allocateDirect(data.size)
            buf.put(data); buf.flip()
            return buf
        }

        override fun path(): String                 = source.path()
        override fun name(): String                 = source.name()
        override fun extension(): String            = source.extension()
        override fun nameWithoutExtension(): String = source.nameWithoutExtension()
        override fun pathWithoutExtension(): String = source.pathWithoutExtension()
        override fun type(): Files.FileType         = source.type()
        override fun exists(): Boolean              = source.exists()
        override fun lastModified(): Long           = source.lastModified()
        override fun isDirectory(): Boolean         = source.isDirectory

        override fun child(name: String): FileHandle   = CryptorFileHandle(source.child(name))
        override fun sibling(name: String): FileHandle = CryptorFileHandle(source.sibling(name))
        override fun parent(): FileHandle              = CryptorFileHandle(source.parent())

        override fun list(): Array<FileHandle> =
            source.list().map { CryptorFileHandle(it) }.toTypedArray()
        override fun list(suffix: String): Array<FileHandle> =
            source.list(suffix).map { CryptorFileHandle(it) }.toTypedArray()
        override fun file(): java.io.File = source.file()
    }
}
