import java.io.File
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction

/** Creates a build-local RoboVM config with all filesystem paths rooted at the source project. */
abstract class PrepareRoboVMConfigTask : DefaultTask() {

    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val sourceConfigFile: RegularFileProperty

    @get:Input
    abstract val projectDirectory: Property<String>

    @get:Input
    abstract val assetsDirectory: Property<String>

    @get:OutputFile
    abstract val outputConfigFile: RegularFileProperty

    @TaskAction
    fun prepare() {
        val source = sourceConfigFile.get().asFile
        val output = outputConfigFile.get().asFile
        val projectDir = File(projectDirectory.get())
        val marker = "\${cryptorAssetsDirectory}"
        var contents = source.readText(Charsets.UTF_8)
        if (!contents.contains(marker)) {
            throw GradleException(
                "[Cryptor] RoboVM config does not contain $marker: ${source.absolutePath}"
            )
        }

        val directoryPattern = Regex("(<directory(?:\\s[^>]*)?>)(.*?)(</directory>)", RegexOption.DOT_MATCHES_ALL)
        contents = directoryPattern.replace(contents) { match ->
            val rawPath = xmlUnescape(match.groupValues[2].trim())
            val path = if (rawPath == marker) assetsDirectory.get() else resolvePath(projectDir, rawPath)
            match.groupValues[1] + xmlEscape(path) + match.groupValues[3]
        }

        val plistPattern = Regex("(<iosInfoPList>)(.*?)(</iosInfoPList>)", RegexOption.DOT_MATCHES_ALL)
        contents = plistPattern.replace(contents) { match ->
            val path = resolvePath(projectDir, xmlUnescape(match.groupValues[2].trim()))
            match.groupValues[1] + xmlEscape(path) + match.groupValues[3]
        }

        val frameworkPathsPattern = Regex("(<frameworkPaths>)(.*?)(</frameworkPaths>)", RegexOption.DOT_MATCHES_ALL)
        contents = frameworkPathsPattern.replace(contents) { group ->
            val pathPattern = Regex("(<path(?:\\s[^>]*)?>)(.*?)(</path>)", RegexOption.DOT_MATCHES_ALL)
            val normalized = pathPattern.replace(group.groupValues[2]) { match ->
                val path = resolvePath(projectDir, xmlUnescape(match.groupValues[2].trim()))
                match.groupValues[1] + xmlEscape(path) + match.groupValues[3]
            }
            group.groupValues[1] + normalized + group.groupValues[3]
        }

        if (contents.contains(marker)) {
            throw GradleException("[Cryptor] Unresolved RoboVM asset directory marker in ${source.absolutePath}")
        }
        output.parentFile.mkdirs()
        output.writeText(contents, Charsets.UTF_8)
    }

    private fun resolvePath(projectDir: File, path: String): String {
        if (path.isEmpty() || path.contains("\${")) return path
        val file = File(path)
        return (if (file.isAbsolute) file else File(projectDir, path)).canonicalPath
    }

    private fun xmlUnescape(value: String): String = value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")

    private fun xmlEscape(value: String): String = value
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
}
