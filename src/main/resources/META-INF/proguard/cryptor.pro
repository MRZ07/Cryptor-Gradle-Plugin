# Cryptor runtime consumer rules — injected automatically into consumer builds.
#
# R8's dead-code analysis removes the key-derived CryptorFilesWrapper / CryptorAudioWrapper
# classes when it determines the stored reference is only used via the Files/Audio interface.
# These rules prevent removal while explicitly ALLOWING obfuscation (class/member names are
# still renamed by R8 — this is intentional, the key-derived names get a second rename pass).
#
# allowobfuscation: renaming still happens (obfuscation preserved).
# The class name itself is key-derived and already obfuscated at build time;
# R8 adds a second rename on top — both levels of obfuscation are active.

-keep,allowobfuscation class * implements com.badlogic.gdx.Files {
    <init>(com.badlogic.gdx.Files);
}

-keep,allowobfuscation class * implements com.badlogic.gdx.Audio {
    <init>(com.badlogic.gdx.Audio);
}
