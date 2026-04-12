/**
 * StringDecryptor — injected into the target project's class output directory at build time.
 *
 * DO NOT add this class manually to your project. The plugin handles injection automatically.
 *
 * The KEY field value (0L) is a placeholder; EncryptClassesTask replaces it with the real
 * project key before writing the class into the output directory.
 */
object StringDecryptor {
    // Placeholder — replaced at injection time by EncryptClassesTask
    private val KEY: Long = 0L

    private val cache = HashMap<String, String>()

    /**
     * Decrypts a string whose bytes were XOR-encrypted and stored as an ISO-8859-1 string literal.
     * ISO_8859_1 is a bijective byte↔char mapping, so all 256 byte values round-trip correctly.
     */
    @JvmStatic
    fun decrypt(encoded: String): String {
        return cache.getOrPut(encoded) {
            val data = encoded.toByteArray(Charsets.ISO_8859_1)
            val key = KEY
            String(ByteArray(data.size) { i ->
                (data[i].toInt() xor ((key shr ((i % 8) * 8)) and 0xFF).toInt()).toByte()
            })
        }
    }
}
