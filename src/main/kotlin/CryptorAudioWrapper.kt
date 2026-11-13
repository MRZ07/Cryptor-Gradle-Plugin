import com.badlogic.gdx.Application
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
 * On iOS, decrypted audio is cached in LibGDX's writable local area because bundle
 * resources are read-only. Other platforms keep their existing temp-file behavior.
 */
class CryptorAudioWrapper(private val delegate: Audio) : Audio by delegate {

    companion object {
        private val materializedCache = ConcurrentHashMap<String, FileHandle>()
        private val audioFileCache = ConcurrentHashMap<String, File>()
        private val cleanupDone = AtomicBoolean(false)

        internal fun usesIOSLocalCache(): Boolean =
            Gdx.app?.type == Application.ApplicationType.iOS

        private fun keyHash(): String {
            val magic = AesFileEncryptor.deriveMagic(CryptorFilesWrapper.masterKey())
            return magic.joinToString("") { "%02x".format(it) }
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

        private fun resolveAudioDir(): File {
            val tmpDir = File(System.getProperty("java.io.tmpdir", "."))
            val baseDir = if (tmpDir.name == "cache" && tmpDir.parentFile != null)
                tmpDir.resolveSibling("files") else tmpDir
            val parentDir = File(baseDir, "cryptor_audio")
            val currentDir = File(parentDir, keyHash())
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

        /**
         * Materialize decrypted bytes in LibGDX's writable local area. iOS bundles are
         * read-only; audio backends and some native loaders need a real filesystem path.
         * The key-scoped directory prevents a cache from an older app key being reused.
         */
        internal fun materialize(kind: String, path: String, bytes: ByteArray): FileHandle {
            val normalizedPath = path.replace('\\', '/')
            val cacheKey = "$kind:$normalizedPath"
            val currentKeyHash = keyHash()
            synchronized(materializedCache) {
                val cached = materializedCache[cacheKey]
                if (cached != null && cached.exists() && cached.length() == bytes.size.toLong()) {
                    return cached
                }

                if (cleanupDone.compareAndSet(false, true)) {
                    val cacheRoot = Gdx.files.local("cryptor")
                    if (cacheRoot.exists()) {
                        cacheRoot.list().forEach { sibling ->
                            if (sibling.isDirectory && sibling.name() != currentKeyHash) {
                                sibling.deleteDirectory()
                            }
                        }
                    }
                }

                val localFile = Gdx.files.local(
                    "cryptor/$currentKeyHash/$kind/${buildCacheFileName(normalizedPath)}"
                )
                localFile.parent().mkdirs()
                localFile.writeBytes(bytes, false)
                if (localFile.length() != bytes.size.toLong()) {
                    localFile.delete()
                    throw GdxRuntimeException(
                        "Decrypted cache size mismatch for $normalizedPath " +
                            "(expected ${bytes.size}, got ${localFile.length()})"
                    )
                }
                materializedCache[cacheKey] = localFile
                return localFile
            }
        }
    }

    override fun newSound(fileHandle: FileHandle): Sound =
        delegate.newSound(toAbsoluteTempHandle(fileHandle))

    override fun newMusic(fileHandle: FileHandle): Music =
        delegate.newMusic(toAbsoluteTempHandle(fileHandle))

    private fun toAbsoluteTempHandle(fileHandle: FileHandle): FileHandle {
        val path   = fileHandle.path()
        if (usesIOSLocalCache()) {
            val cacheKey = "audio:${path.replace('\\', '/')}"
            val cached = materializedCache[cacheKey]
            if (cached != null && cached.exists() && cached.length() > 0L) {
                return Gdx.files.absolute(cached.file().absolutePath)
            }

            val bytes = fileHandle.readBytes()
            if (bytes.isEmpty()) {
                throw GdxRuntimeException("Decrypted audio file is empty: $path")
            }
            val localFile = materialize("audio", path, bytes)
            return Gdx.files.absolute(localFile.file().absolutePath)
        }

        val cached = audioFileCache[path]
        if (cached != null && cached.exists() && cached.length() > 0L) {
            return Gdx.files.absolute(cached.absolutePath)
        }

        val bytes = fileHandle.readBytes()
        if (bytes.isEmpty()) {
            throw GdxRuntimeException("Decrypted audio file is empty: $path")
        }

        val file = File(resolveAudioDir(), buildCacheFileName(path))
        FileOutputStream(file).use { output ->
            output.write(bytes)
            output.flush()
            output.fd.sync()
        }
        if (file.length() != bytes.size.toLong()) {
            file.delete()
            throw GdxRuntimeException(
                "Audio size mismatch for $path (expected ${bytes.size}, got ${file.length()})"
            )
        }
        audioFileCache[path] = file
        return Gdx.files.absolute(file.absolutePath)
    }
}
