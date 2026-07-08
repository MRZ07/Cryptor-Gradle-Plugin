import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class CryptorAudioWrapperTest {

    @Test
    fun cacheFileName_staysShort_forVeryLongAssetPath() {
        val longPath = buildString {
            append("sounds/")
            repeat(32) { idx ->
                append("screen_section_")
                append(idx)
                append('_')
                append("very_long_descriptor")
                append('/')
            }
            append("title/start.mp3")
        }

        val fileName = CryptorAudioWrapper.buildCacheFileName(longPath)

        assertTrue(fileName.length <= 120, "filename too long: ${fileName.length}")
        assertTrue(fileName.endsWith(".mp3"), "extension must be preserved")
    }

    @Test
    fun cacheFileName_isDeterministic_andDiffersByPath() {
        val pathA = "sounds/ui/screen/title/start.mp3"
        val pathB = "sounds/ui/screen/title/end.mp3"

        val nameA1 = CryptorAudioWrapper.buildCacheFileName(pathA)
        val nameA2 = CryptorAudioWrapper.buildCacheFileName(pathA)
        val nameB = CryptorAudioWrapper.buildCacheFileName(pathB)

        assertEquals(nameA1, nameA2)
        assertNotEquals(nameA1, nameB)
    }
}
