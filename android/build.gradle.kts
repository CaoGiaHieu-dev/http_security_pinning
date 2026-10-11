group = "dev.hieucg.http_security_pinning"
version = "2.0.0"

buildscript {
    repositories {
        google()
        mavenCentral()
    }

    dependencies {
        classpath("com.android.tools.build:gradle:9.1.0")
    }
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

plugins {
    id("com.android.library")
}

android {
    namespace = "dev.hieucg.http_security_pinning"

    compileSdk = 36

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        minSdk = 24
    }

    lint {
        // The probe's trust manager must never be flagged as trust-all.
        error += "TrustAllX509TrustManager"
        error += "BadHostnameVerifier"
        abortOnError = true
    }

    testOptions {
        unitTests.all {
            it.outputs.upToDateWhen { false }
            it.systemProperty("fixturesDir", file("../test/fixtures").absolutePath)
            it.testLogging {
                events("passed", "skipped", "failed", "standardOut", "standardError")
                showStandardStreams = true
            }
        }
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.mockito:mockito-core:5.0.0")
}
