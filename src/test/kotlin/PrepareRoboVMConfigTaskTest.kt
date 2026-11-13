import java.io.File
import org.gradle.testfixtures.ProjectBuilder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PrepareRoboVMConfigTaskTest {

    @Test
    fun createsAbsoluteAssetAndRelativeConfigPathsWithoutChangingSource() {
        val root = File(
            System.getProperty("java.io.tmpdir"),
            "cryptor-robovm-config-${System.nanoTime()}"
        )
        val source = File(root, "robovm.xml")
        val output = File(root, "build/cryptor/robovm.xml")
        val original = """
            <config>
              <iosInfoPList>Info.plist.xml</iosInfoPList>
              <resources>
                <resource><directory>${'$'}{cryptorAssetsDirectory}</directory></resource>
                <resource><directory>data</directory></resource>
              </resources>
              <frameworkPaths><path variant="simulator">libs/sim</path></frameworkPaths>
            </config>
        """.trimIndent()
        source.parentFile.mkdirs()
        source.writeText(original, Charsets.UTF_8)

        try {
            val task = ProjectBuilder.builder().build().tasks.create(
                "prepareRobovmConfig",
                PrepareRoboVMConfigTask::class.java
            )
            task.sourceConfigFile.set(source)
            task.projectDirectory.set(root.absolutePath)
            task.assetsDirectory.set("/private/app/encrypted&assets")
            task.outputConfigFile.set(output)

            task.prepare()

            val generated = output.readText(Charsets.UTF_8)
            assertTrue(generated.contains("/private/app/encrypted&amp;assets"))
            assertTrue(generated.contains(File(root, "data").canonicalPath))
            assertTrue(generated.contains(File(root, "Info.plist.xml").canonicalPath))
            assertTrue(generated.contains(File(root, "libs/sim").canonicalPath))
            assertFalse(generated.contains("${'$'}{cryptorAssetsDirectory}"))
            assertEquals(original, source.readText(Charsets.UTF_8))
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun failsWhenTheConfigHasNoAssetDirectoryMarker() {
        val root = File(
            System.getProperty("java.io.tmpdir"),
            "cryptor-robovm-config-missing-${System.nanoTime()}"
        )
        val source = File(root, "robovm.xml")
        val output = File(root, "build/cryptor/robovm.xml")
        source.parentFile.mkdirs()
        source.writeText("<config/>", Charsets.UTF_8)

        try {
            val task = ProjectBuilder.builder().build().tasks.create(
                "prepareRobovmConfig",
                PrepareRoboVMConfigTask::class.java
            )
            task.sourceConfigFile.set(source)
            task.projectDirectory.set(root.absolutePath)
            task.assetsDirectory.set("/private/app/encrypted-assets")
            task.outputConfigFile.set(output)

            assertFailsWith<org.gradle.api.GradleException> { task.prepare() }
        } finally {
            root.deleteRecursively()
        }
    }
}
