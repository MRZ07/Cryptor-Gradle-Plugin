import kotlin.test.Test
import kotlin.test.assertEquals

class CryptorKeyTest {

    @Test
    fun `default key is the documented 0xDEADBEEFCAFEBABE`() {
        assertEquals(0xDEADBEEFCAFEBABEUL.toLong(), CryptorPlugin.DEFAULT_KEY)
    }
}
