import java.util.concurrent.ConcurrentHashMap

/**
 * StringDecryptor — injected into the target project's class output at build time.
 *
 * Encrypted string format (ISO-8859-1 chars):
 *   chars [0..7]   8-byte salt = murmur64(original UTF-8 plaintext), little-endian
 *   chars [8..]    XOR-encrypted UTF-8 bytes using derivedKey = KEY xor salt
 *
 * KEY is patched at build time via PUTSTATIC in <clinit> by EncryptClassesTask.
 * Per-string salt means recovering one string's key does not help decrypt others.
 *
 * Thread safety: putIfAbsent used instead of computeIfAbsent to avoid a dependency
 * on java.util.function.Function, which is not available in RoboVM's iOS runtime.
 */
object StringDecryptor {
    @JvmField var KEY: Long = 0L

    private val cache = ConcurrentHashMap<String, String>()

    @JvmStatic
    fun decrypt(encoded: String): String {
        cache[encoded]?.let { return it }

        var salt = 0L
        for (i in 0 until 8) {
            salt = salt or ((encoded[i].code.toLong() and 0xFF) shl (i * 8))
        }
        val derivedKey = KEY xor salt

        val data      = encoded.substring(8).toByteArray(Charsets.ISO_8859_1)
        val decrypted = ByteArray(data.size) { i ->
            val kb = ((derivedKey ushr ((i % 8) * 8)) and 0xFF).toInt()
            (data[i].toInt() xor kb).toByte()
        }
        val result = String(decrypted, Charsets.UTF_8)

        return cache.putIfAbsent(encoded, result) ?: result
    }
}
