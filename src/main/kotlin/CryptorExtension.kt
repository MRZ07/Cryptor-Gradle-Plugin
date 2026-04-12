import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property

abstract class CryptorExtension {
    /**
     * Master switch. When false the plugin is completely inactive — no string encryption,
     * no asset encryption, no class injection. Useful to quickly compare obfuscated vs
     * plain builds without removing the plugin block.
     */
    abstract val enabled: Property<Boolean>

    /** 64-bit XOR key used to encrypt string literals. Change per project. */
    abstract val key: Property<Long>

    /**
     * Additional package prefixes (slash-separated) to exclude from transformation.
     * Kotlin internals, JDK, and Android framework are always excluded automatically.
     */
    abstract val excludePackages: ListProperty<String>

    /**
     * When true (default), debug build variants are skipped so that stack traces
     * remain readable and iteration is fast.
     */
    abstract val skipDebug: Property<Boolean>

    /** When true (default), string literals in class files are XOR-encrypted at build time. */
    abstract val encryptStrings: Property<Boolean>

    /** When true (default), asset files in assetsDir are XOR-encrypted at build time. */
    abstract val encryptAssets: Property<Boolean>

    /** Directory containing the game assets. Defaults to a folder named "assets" next to the project root. */
    abstract val assetsDir: DirectoryProperty

    /**
     * File extensions to encrypt. All other files are copied as-is.
     * Defaults cover common LibGDX asset types including audio.
     */
    abstract val assetExtensions: ListProperty<String>

    init {
        enabled.convention(true)
        key.convention(0xDEADBEEFCAFEBABEUL.toLong())
        excludePackages.convention(emptyList())
        skipDebug.convention(true)
        encryptStrings.convention(true)
        encryptAssets.convention(true)
        assetExtensions.convention(listOf(
            "tmx", "png", "jpg", "jpeg",
            "atlas", "pack", "json", "fnt", "ttf", "properties",
            "mp3", "ogg", "wav"
        ))
    }
}
