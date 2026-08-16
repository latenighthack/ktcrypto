import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidLibrary)
    id("com.vanniktech.maven.publish.base")
    id("io.github.ttypic.swiftklib") version "0.6.3"
}

// Unique archive base name so the published jvm/js artifacts are `ktcrypto-library-*` rather than the
// generic `library-*` (the project name). Otherwise two `:library` modules at the same version (e.g.
// ktcrypto + ktstore both 0.0.8) collide as `library-jvm-<v>.jar` in a consumer's application
// distribution, which Gradle 9 rejects as a duplicate.
base { archivesName.set("ktcrypto-library") }

kotlin {
    js {
        browser()
    }
    jvm {
    }
    androidTarget {
        publishLibraryVariants("release")
        @OptIn(ExperimentalKotlinGradlePluginApi::class)
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_1_8)
        }
    }
    listOf(
        iosX64(),
        iosArm64(),
        iosSimulatorArm64()
    ).forEach {
        it.compilations {
            val main by getting {
                cinterops {
                    create("KtCrypto")
                }
            }
        }
    }


    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(libs.kotlinx.coroutines.core)
            }
        }
        val jvmMain by getting {
            dependencies {
                implementation(libs.bouncycastle.jvm)
            }
        }
        val androidMain by getting {
            dependencies {
                implementation(libs.bouncycastle)
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(libs.kotlin.test)
            }
        }
    }
}

android {
    namespace = "com.latenighthack.ktcrypto"
    compileSdk = libs.versions.android.compileSdk.get().toInt()
    defaultConfig {
        minSdk = libs.versions.android.minSdk.get().toInt()
    }
}

mavenPublishing {
    coordinates("com.latenighthack.ktcrypto", "ktcrypto-library", version.toString())

    pom {
        name.set("ktcrypto")
        description.set("A native Kotlin implementation of protocol buffers")
        inceptionYear.set("2024")
        url.set("https://github.com/latenighthack/ktcrypto/")
        licenses {
            license {
                name.set("The Apache License, Version 2.0")
                url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                distribution.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
            }
        }
        developers {
            developer {
                id.set("mproberts")
                name.set("Mike Roberts")
                url.set("https://github.com/mproberts/")
            }
        }
        scm {
            url.set("https://github.com/latenighthack/ktcrypto/")
            connection.set("scm:git:git://github.com/latenighthack/ktcrypto.git")
            developerConnection.set("scm:git:ssh://git@github.com/latenighthack/ktcrypto.git")
        }
    }
}

swiftklib {
    create("KtCrypto") {
        path = file("native/KtCrypto")
        packageName("com.latenighthack.objclibs.ktcrypto")
        minIos = 16 // CryptoKit compressedRepresentation (SEC1) requires iOS 16+
    }
}