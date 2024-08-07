import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidLibrary)
    id("com.vanniktech.maven.publish.base")
}

kotlin {
    js {
        browser()
    }
    androidTarget {
        publishLibraryVariants("release")
        @OptIn(ExperimentalKotlinGradlePluginApi::class)
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_1_8)
        }
    }
    iosX64()
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(libs.kotlinx.coroutines.core)
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
    coordinates("com.latenighthack.ktcrypto", "ktcrypto-library", "0.0.1")

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
