import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * StringDecryptor — injected into the target project's class output at build time.
 *
 * Encrypted string format (ISO-8859-1 chars):
 *   chars [0..7]   8-byte IV prefix = murmur64(plaintext UTF-8 bytes), little-endian
 *   chars [8..]    AES-128-CTR ciphertext
 *
 * The 16-byte AES key is reconstructed from KEY_0..KEY_3 (patched at build time via
 * arithmetic veil), then derived via SHA-256 to produce the final cipher key.
 * KEY fields are zeroed after the key is assembled to reduce heap exposure.
 *
 * Thread safety: ConcurrentHashMap.computeIfAbsent is atomic — safe for parallel
 * calls from LibGDX async asset-loader threads.
 */
object StringDecryptor {
    // Patched at build time by EncryptClassesTask via PUTSTATIC in <clinit>.
    // Private to prevent casual getDeclaredField() access without setAccessible().
    @JvmField private var KEY_0: Int = 0
    @JvmField private var KEY_1: Int = 0
    @JvmField private var KEY_2: Int = 0
    @JvmField private var KEY_3: Int = 0

    private val cipherKey: ByteArray by lazy {
        val buf = ByteBuffer.allocate(16)
        buf.putInt(KEY_0); buf.putInt(KEY_1); buf.putInt(KEY_2); buf.putInt(KEY_3)
        KEY_0 = 0; KEY_1 = 0; KEY_2 = 0; KEY_3 = 0
        MessageDigest.getInstance("SHA-256").digest(buf.array()).copyOf(16)
    }

    private val cache = ConcurrentHashMap<String, String>()

    @JvmStatic
    fun decrypt(encoded: String): String =
        cache.computeIfAbsent(encoded) { enc ->
            val ivPrefix = ByteArray(8) { i -> (enc[i].code and 0xFF).toByte() }
            val iv       = ivPrefix + ivPrefix          // pad to 16 bytes
            val data     = enc.substring(8).toByteArray(Charsets.ISO_8859_1)
            val cipher   = Cipher.getInstance("AES/CTR/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(cipherKey, "AES"), IvParameterSpec(iv))
            String(cipher.doFinal(data), Charsets.UTF_8)
        }
}
