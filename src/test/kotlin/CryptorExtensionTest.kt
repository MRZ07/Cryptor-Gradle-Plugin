import org.gradle.testfixtures.ProjectBuilder
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CryptorExtensionTest {

    @Test
    fun injectFilesWrapperDefaultsToAssetEncryptionSetting() {
        val project = ProjectBuilder.builder().build()
        val extension = project.extensions.create("cryptor", CryptorExtension::class.java)

        assertTrue(extension.injectFilesWrapper.get())
        extension.encryptAssets.set(false)
        assertFalse(extension.injectFilesWrapper.get())

        extension.encryptAssets.set(true)
        assertTrue(extension.injectFilesWrapper.get())
    }
}
