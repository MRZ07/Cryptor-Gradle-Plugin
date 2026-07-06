import java.util.concurrent.ConcurrentHashMap

/**
 * StringDecryptor — injected into the target project's class output at build time.
 *
 * Encrypted string format (ISO-8859-1):
 *   chars [0..7]  salt bytes (little-endian Long = murmur64 of original UTF-8 bytes)
 *   chars [8..]   XOR-encrypted UTF-8 bytes using (KEY XOR salt)
 *
 * Per-string derivation means all strings must be individually attacked — a single
 * KEY recovery does not bulk-decrypt the binary.
 *
 * Thread safety: ConcurrentHashMap.computeIfAbsent is used instead of HashMap.getOrPut
 * so that concurrent access from LibGDX async asset-loader threads is race-free.
 */
object StringDecryptor {
    // Placeholder — replaced at injection time by EncryptClassesTask
    private val KEY: Long = 0L

    private val cache = ConcurrentHashMap<String, String>()

    @JvmStatic
    fun decrypt(encoded: String): String =
        cache.computeIfAbsent(encoded) { enc ->
            // Extract 8-byte salt stored in the first 8 ISO-8859-1 chars
            var salt = 0L
            for (i in 0 until 8) {
                salt = salt or ((enc[i].code.toLong() and 0xFF) shl (i * 8))
            }
            val derivedKey = KEY xor salt

            // Decrypt remaining bytes
            val data = enc.substring(8).toByteArray(Charsets.ISO_8859_1)
            String(ByteArray(data.size) { i ->
                (data[i].toInt() xor ((derivedKey ushr ((i % 8) * 8)) and 0xFF).toInt()).toByte()
            })
        }
}
