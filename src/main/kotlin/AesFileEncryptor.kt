import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-128-CTR asset encryption with per-file derived keys and per-project magic.
 *
 * Header layout (24 bytes):
 *   [0..3]   magic = sha256(masterKey)[0:4]  — unique per project key
 *   [4..7]   plaintext length (big endian)
 *   [8..23]  random IV (16 bytes)
 *   [24..]   AES-128-CTR ciphertext
 *
 * AES-CTR is length preserving, so the stored plaintext length is a free integrity check: a
 * truncated or padded asset (an interrupted install, a partial copy, a bad packaging step) is
 * reported as corruption instead of being decrypted into a shorter stream and handed to a
 * decoder as "not of any known type".
 */
object AesFileEncryptor {

    const val MAGIC_SIZE = 4
    const val LENGTH_SIZE = 4
    const val IV_SIZE = 16
    const val HEADER_SIZE = MAGIC_SIZE + LENGTH_SIZE + IV_SIZE  // 24
    private const val IV_OFFSET = MAGIC_SIZE + LENGTH_SIZE

    /** An encrypted asset whose stored plaintext length does not match its ciphertext length. */
    class AssetCorruptionException(message: String) : RuntimeException(message)

    // -------------------------------------------------------------------------
    // Key derivation
    // -------------------------------------------------------------------------

    fun deriveAesKey(longKey: Long): ByteArray {
        val keyBytes = ByteBuffer.allocate(8).putLong(longKey).array()
        return sha256(keyBytes).copyOf(16)
    }

    fun deriveFileKey(masterKey: ByteArray, relativePath: String): ByteArray {
        val normalized = relativePath.lowercase().replace('\\', '/')
        val md = MessageDigest.getInstance("SHA-256")
        md.update(masterKey)
        md.update(normalized.toByteArray(Charsets.UTF_8))
        return md.digest().copyOf(16)
    }

    /** Per-project magic: first 4 bytes of SHA-256(masterKey). */
    fun deriveMagic(masterKey: ByteArray): ByteArray = sha256(masterKey).copyOf(MAGIC_SIZE)

    // -------------------------------------------------------------------------
    // Encrypt / Decrypt
    // -------------------------------------------------------------------------

    fun encrypt(data: ByteArray, masterKey: ByteArray, relativePath: String): ByteArray {
        val magic   = deriveMagic(masterKey)
        val fileKey = deriveFileKey(masterKey, relativePath)
        val iv      = ByteArray(IV_SIZE).also { SecureRandom().nextBytes(it) }
        val header  = ByteBuffer.allocate(HEADER_SIZE)
            .put(magic)
            .putInt(data.size)
            .put(iv)
            .array()
        return header + aesCtr(data, fileKey, iv, Cipher.ENCRYPT_MODE)
    }

    fun decrypt(raw: ByteArray, masterKey: ByteArray, relativePath: String): ByteArray {
        if (!hasMagic(raw, masterKey)) return raw
        val storedLength = ByteBuffer.wrap(raw, MAGIC_SIZE, LENGTH_SIZE).int
        val ciphertextLength = raw.size - HEADER_SIZE
        if (storedLength < 0 || ciphertextLength != storedLength) {
            throw AssetCorruptionException(
                "Encrypted asset '${relativePath.replace('\\', '/')}' is corrupt: header declares " +
                    "$storedLength plaintext bytes but the file carries $ciphertextLength. " +
                    "Reinstall the app; if it persists the shipped asset is truncated."
            )
        }
        val iv         = raw.copyOfRange(IV_OFFSET, HEADER_SIZE)
        val ciphertext = raw.copyOfRange(HEADER_SIZE, raw.size)
        val fileKey    = deriveFileKey(masterKey, relativePath)
        return aesCtr(ciphertext, fileKey, iv, Cipher.DECRYPT_MODE)
    }

    fun hasMagic(raw: ByteArray, masterKey: ByteArray): Boolean {
        if (raw.size < HEADER_SIZE) return false
        val magic = deriveMagic(masterKey)
        return raw[0] == magic[0] && raw[1] == magic[1] &&
               raw[2] == magic[2] && raw[3] == magic[3]
    }

    /**
     * Whether [raw] carries a complete current-format header.
     *
     * AES-CTR is length preserving, so the stored plaintext length must equal the ciphertext
     * length. A file that has the magic but not the invariant is an older format or a truncated
     * copy; the build treats it as a stale artefact instead of shipping it.
     */
    fun isWellFormed(raw: ByteArray): Boolean {
        if (raw.size < HEADER_SIZE) return false
        val storedLength = ByteBuffer.wrap(raw, MAGIC_SIZE, LENGTH_SIZE).int
        return storedLength >= 0 && raw.size - HEADER_SIZE == storedLength
    }

    // -------------------------------------------------------------------------
    // Key reconstruction from four split Int fields (runtime)
    // -------------------------------------------------------------------------

    fun masterKeyFromInts(k0: Int, k1: Int, k2: Int, k3: Int): ByteArray {
        val buf = ByteBuffer.allocate(16)
        buf.putInt(k0); buf.putInt(k1); buf.putInt(k2); buf.putInt(k3)
        return buf.array()
    }

    fun splitKey(keyBytes: ByteArray): IntArray {
        require(keyBytes.size == 16) { "Key must be 16 bytes" }
        val buf = ByteBuffer.wrap(keyBytes)
        return intArrayOf(buf.getInt(), buf.getInt(), buf.getInt(), buf.getInt())
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    private fun aesCtr(data: ByteArray, key: ByteArray, iv: ByteArray, mode: Int): ByteArray {
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(mode, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(data)
    }
}
