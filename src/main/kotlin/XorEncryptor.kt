/**
 * XorEncryptor — retained for any byte-level callers.
 * String encryption has moved to AES-128-CTR in [EncryptClassesTask].
 * [murmur64] is used to derive the IV prefix for AES string encryption.
 */
object XorEncryptor {

    fun encrypt(bytes: ByteArray, key: Long): ByteArray =
        ByteArray(bytes.size) { i ->
            val kb = ((key ushr ((i % 8) * 8)) and 0xFF).toInt()
            (bytes[i].toInt() xor kb).toByte()
        }

    // -------------------------------------------------------------------------
    // 64-bit hash — deterministic, no external deps
    // Used to derive the AES IV prefix for string encryption.
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
