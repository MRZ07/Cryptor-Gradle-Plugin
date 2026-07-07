/**
 * String encryption: per-string derived key via murmur64 salt.
 *
 * Salt = murmur64(plaintext UTF-8 bytes). Stored as the first 8 bytes of output.
 * derivedKey = configKey XOR salt
 *
 * This ensures that recovering one string's key does not help decrypt any other string.
 * StringDecryptor mirrors this logic at runtime.
 */
object XorEncryptor {

    /**
     * Encrypts [value] for injection as a class-file LDC constant.
     * Returns [salt (8 bytes)] + [XOR-encrypted UTF-8 plaintext].
     */
    fun encrypt(value: String, key: Long): ByteArray {
        val plainBytes = value.toByteArray(Charsets.UTF_8)
        val salt       = murmur64(plainBytes)
        val derivedKey = key xor salt
        val saltBytes  = ByteArray(8) { i -> ((salt ushr (i * 8)) and 0xFF).toByte() }
        val encrypted  = ByteArray(plainBytes.size) { i ->
            val kb = ((derivedKey ushr ((i % 8) * 8)) and 0xFF).toInt()
            (plainBytes[i].toInt() xor kb).toByte()
        }
        return saltBytes + encrypted
    }

    /** Raw byte-level XOR (retained for any direct byte-level callers). */
    fun encrypt(bytes: ByteArray, key: Long): ByteArray =
        ByteArray(bytes.size) { i ->
            val kb = ((key ushr ((i % 8) * 8)) and 0xFF).toInt()
            (bytes[i].toInt() xor kb).toByte()
        }

    // -------------------------------------------------------------------------
    // 64-bit hash — deterministic, no external deps
    // -------------------------------------------------------------------------
    internal fun murmur64(data: ByteArray): Long {
        var h = -0x6C62272E07BB0142L
        for (b in data) {
            h  = h xor (b.toLong() and 0xFF)
            h *= -0x61C8864680B583EBL
            h  = (h shl 31) or (h ushr 33)
            h *= -0x6B2FB644ECCECEBBL
        }
        h  = h xor data.size.toLong()
        h  = h xor (h ushr 33)
        h *= -0xAE502812AA7333L
        h  = h xor (h ushr 33)
        h *= -0x3B314601E57A13ADL
        h  = h xor (h ushr 33)
        return h
    }
}
