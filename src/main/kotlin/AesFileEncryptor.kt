import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-128-CTR asset encryption with per-file derived keys and per-project magic.
 *
 * Header layout (20 bytes):
 *   [0..3]   magic = sha256(masterKey)[0:4]  — unique per project key
 *   [4..19]  random IV (16 bytes)
 *   [20..]   AES-128-CTR ciphertext
 */
object AesFileEncryptor {

    const val HEADER_SIZE = 20  // 4 magic + 16 IV

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
    fun deriveMagic(masterKey: ByteArray): ByteArray = sha256(masterKey).copyOf(4)

    // -------------------------------------------------------------------------
    // Encrypt / Decrypt
    // -------------------------------------------------------------------------

    fun encrypt(data: ByteArray, masterKey: ByteArray, relativePath: String): ByteArray {
        val magic   = deriveMagic(masterKey)
        val fileKey = deriveFileKey(masterKey, relativePath)
        val iv      = ByteArray(16).also { SecureRandom().nextBytes(it) }
        return magic + iv + aesCtr(data, fileKey, iv, Cipher.ENCRYPT_MODE)
    }

    fun decrypt(raw: ByteArray, masterKey: ByteArray, relativePath: String): ByteArray {
        if (!hasMagic(raw, masterKey)) return raw
        val iv         = raw.copyOfRange(4, 20)
        val ciphertext = raw.copyOfRange(20, raw.size)
        val fileKey    = deriveFileKey(masterKey, relativePath)
        return aesCtr(ciphertext, fileKey, iv, Cipher.DECRYPT_MODE)
    }

    fun hasMagic(raw: ByteArray, masterKey: ByteArray): Boolean {
        if (raw.size < HEADER_SIZE) return false
        val magic = deriveMagic(masterKey)
        return raw[0] == magic[0] && raw[1] == magic[1] &&
               raw[2] == magic[2] && raw[3] == magic[3]
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
