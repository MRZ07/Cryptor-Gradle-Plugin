import java.nio.ByteBuffer
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
 * The 16-byte AES cipher key is assembled directly from KEY_0..KEY_3 (patched at
 * build time via arithmetic veil by EncryptClassesTask). The fields already contain
 * the final derived key — no additional derivation step here.
 * KEY fields are zeroed immediately after assembly to reduce heap exposure.
 *
 * Thread safety: putIfAbsent used instead of computeIfAbsent to avoid a dependency
 * on java.util.function.Function, which is not available in RoboVM's iOS runtime.
 */
object StringDecryptor {
    @JvmField var KEY_0: Int = 0
    @JvmField var KEY_1: Int = 0
    @JvmField var KEY_2: Int = 0
    @JvmField var KEY_3: Int = 0

    private val cipherKey: ByteArray by lazy {
        val buf = ByteBuffer.allocate(16)
        buf.putInt(KEY_0); buf.putInt(KEY_1); buf.putInt(KEY_2); buf.putInt(KEY_3)
        KEY_0 = 0; KEY_1 = 0; KEY_2 = 0; KEY_3 = 0
        // KEY_0..KEY_3 already hold AesFileEncryptor.deriveAesKey(longKey) split into ints.
        // Do NOT derive again — double-derivation produces a mismatched key.
        buf.array()
    }

    private val cache = ConcurrentHashMap<String, String>()

    @JvmStatic
    fun decrypt(encoded: String): String {
        // Fast path — already cached.
        cache[encoded]?.let { return it }

        val ivPrefix = ByteArray(8) { i -> (encoded[i].code and 0xFF).toByte() }
        val iv       = ivPrefix + ivPrefix   // pad 8 → 16 bytes
        val data     = encoded.substring(8).toByteArray(Charsets.ISO_8859_1)
        val cipher   = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(cipherKey, "AES"), IvParameterSpec(iv))
        val decrypted = String(cipher.doFinal(data), Charsets.UTF_8)

        // putIfAbsent avoids java.util.function.Function (not available on RoboVM / iOS).
        // If another thread raced us, return the winner's value; both are identical.
        return cache.putIfAbsent(encoded, decrypted) ?: decrypted
    }
}
