import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertContentEquals
import java.util.Locale

class CryptorKeyTest {

    @Test
    fun `default key is the documented 0xDEADBEEFCAFEBABE`() {
        assertEquals(0xDEADBEEFCAFEBABEUL.toLong(), CryptorPlugin.DEFAULT_KEY)
    }

    @Test
    fun `file key derivation is stable under Turkish default locale`() {
        val previous = Locale.getDefault()
        val key = ByteArray(16) { it.toByte() }
        val path = "Images/ICON_I.PNG"
        try {
            Locale.setDefault(Locale.ROOT)
            val expected = AesFileEncryptor.deriveFileKey(key, path)
            Locale.setDefault(Locale.forLanguageTag("tr"))
            assertContentEquals(expected, AesFileEncryptor.deriveFileKey(key, path))
        } finally {
            Locale.setDefault(previous)
        }
    }
}
