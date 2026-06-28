import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-128-CTR asset encryption with per-file derived keys.
 *
 * Security properties:
 *  - AES-128-CTR: known-plaintext does not recover the key (computationally infeasible)
 *  - Per-file derived key: recovering one file's key does not help with other files
 *  - Random 16-byte IV per file: identical assets produce different ciphertexts
 *
 * Header layout (20 bytes):
 *   [0..3]   magic  C0 DE CA FE
 *   [4..19]  random IV (16 bytes)
 *   [20..]   AES-128-CTR ciphertext
 */
object AesFileEncryptor {

    val MAGIC = byteArrayOf(0xC0.toByte(), 0xDE.toByte(), 0xCA.toByte(), 0xFE.toByte())
    const val HEADER_SIZE = 20  // 4 magic + 16 IV

    // -------------------------------------------------------------------------
    // Key derivation
    // -------------------------------------------------------------------------

    /**
     * Derives a 16-byte AES-128 master key from the user-supplied 64-bit config key.
     * Uses SHA-256 so the 64-bit input is properly expanded; first 16 bytes of digest.
     */
    fun deriveAesKey(longKey: Long): ByteArray {
        val keyBytes = ByteBuffer.allocate(8).putLong(longKey).array()
        return sha256(keyBytes).copyOf(16)
    }

    /**
     * Derives a file-specific 16-byte key: SHA-256(masterKey ∥ normalizedPath)[0:16].
     * Recovering one file's keystream does not expose the master key or other files.
     */
    fun deriveFileKey(masterKey: ByteArray, relativePath: String): ByteArray {
        val normalized = relativePath.lowercase().replace('\\', '/')
        val md = MessageDigest.getInstance("SHA-256")
        md.update(masterKey)
        md.update(normalized.toByteArray(Charsets.UTF_8))
        return md.digest().copyOf(16)
    }

    // -------------------------------------------------------------------------
    // Encrypt / Decrypt
    // -------------------------------------------------------------------------

    /**
     * Encrypts [data] for the asset at [relativePath].
     * Output: MAGIC (4) + random IV (16) + AES-128-CTR ciphertext (N).
     */
    fun encrypt(data: ByteArray, masterKey: ByteArray, relativePath: String): ByteArray {
        val fileKey = deriveFileKey(masterKey, relativePath)
        val iv = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val ciphertext = aesCtr(data, fileKey, iv, Cipher.ENCRYPT_MODE)
        return MAGIC + iv + ciphertext
    }

    /**
     * Decrypts [raw] if it starts with [MAGIC]; otherwise returns [raw] unchanged.
     * [relativePath] must match the path used at encryption time.
     */
    fun decrypt(raw: ByteArray, masterKey: ByteArray, relativePath: String): ByteArray {
        if (!hasMagic(raw)) return raw
        val iv = raw.copyOfRange(4, 20)
        val ciphertext = raw.copyOfRange(20, raw.size)
        val fileKey = deriveFileKey(masterKey, relativePath)
        return aesCtr(ciphertext, fileKey, iv, Cipher.DECRYPT_MODE)
    }

    fun hasMagic(raw: ByteArray): Boolean =
        raw.size >= HEADER_SIZE &&
        raw[0] == MAGIC[0] && raw[1] == MAGIC[1] &&
        raw[2] == MAGIC[2] && raw[3] == MAGIC[3]

    // -------------------------------------------------------------------------
    // Key reconstruction from four split Int fields (used at runtime)
    // -------------------------------------------------------------------------

    /**
     * Reconstructs the 16-byte master key from the four Int fields patched by ASM.
     * Layout: KEY_0 = bytes 0-3 (most significant), KEY_3 = bytes 12-15 (least significant).
     */
    fun masterKeyFromInts(k0: Int, k1: Int, k2: Int, k3: Int): ByteArray {
        val buf = ByteBuffer.allocate(16)
        buf.putInt(k0); buf.putInt(k1); buf.putInt(k2); buf.putInt(k3)
        return buf.array()
    }

    /**
     * Splits a 16-byte key into four Ints (for ASM patching).
     */
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
