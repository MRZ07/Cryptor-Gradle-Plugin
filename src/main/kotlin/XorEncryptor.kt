/**
 * Encrypts a plain-text string into a byte array using a 64-bit XOR key.
 *
 * The key is applied byte-by-byte, rotating through all 8 bytes of the Long.
 * StringDecryptor uses the same algorithm to reverse the operation at runtime.
 */
object XorEncryptor {
    fun encrypt(value: String, key: Long): ByteArray {
        val bytes = value.toByteArray(Charsets.UTF_8)
        return encrypt(bytes, key)
    }

    fun encrypt(bytes: ByteArray, key: Long): ByteArray {
        return ByteArray(bytes.size) { i ->
            val keyByte = ((key shr ((i % 8) * 8)) and 0xFF).toInt()
            (bytes[i].toInt() xor keyByte).toByte()
        }
    }
}
