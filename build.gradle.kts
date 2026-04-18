plugins {
    `java-gradle-plugin`
    `maven-publish`
    kotlin("jvm") version "1.9.23"
}

group   = "com.github.MRZ07"
version = "v1.7.7"

repositories {
    mavenCentral()
    google()
    maven { url = uri("https://central.sonatype.com/repository/maven-snapshots/") }
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

kotlin {
    jvmToolchain(21)
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
    }
}

dependencies {
    implementation("org.ow2.asm:asm:9.7")
    implementation("org.ow2.asm:asm-commons:9.7")
    compileOnly("com.android.tools.build:gradle:8.3.0")
    compileOnly("org.jetbrains.kotlin:kotlin-gradle-plugin:1.9.23")
    compileOnly("com.badlogicgames.gdx:gdx:1.14.0")
}

gradlePlugin {
    plugins {
        create("cryptor") {
            id                  = "com.github.MRZ07.Cryptor-Gradle-Plugin"
            implementationClass = "CryptorPlugin"
        }
    }
}
