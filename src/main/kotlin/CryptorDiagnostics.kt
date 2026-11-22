import com.badlogic.gdx.Gdx

/**
 * Opt-in runtime diagnostics for the decrypt path.
 *
 * Enable with `-Dcryptor.diagnostics=true` (or `System.setProperty` before `Gdx` is created).
 * It exists because a corrupted asset on a user device cannot be reproduced from the build: the
 * log names the asset, its size and whether it decrypted, which is what an affected-device report
 * needs. Silent when the flag is absent, so release builds stay quiet.
 */
internal object CryptorDiagnostics {

    private val enabled: Boolean by lazy {
        System.getProperty("cryptor.diagnostics")?.toBoolean() == true
    }

    fun log(message: String) {
        if (!enabled) return
        Gdx.app?.log("Cryptor", message)
    }
}
