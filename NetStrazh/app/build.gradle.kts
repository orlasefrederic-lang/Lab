plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// CI passes the run number so every build can be installed over the previous one.
val buildNumber = (System.getenv("BUILD_NUMBER") ?: "0").toInt()

android {
    namespace = "lab.netstrazh"
    compileSdk = 35

    defaultConfig {
        applicationId = "lab.netstrazh"
        minSdk = 29
        targetSdk = 34
        versionCode = 100 + buildNumber
        versionName = "1.0.$buildNumber"
    }

    signingConfigs {
        // Shared key so builds from any machine update each other (see README).
        create("shared") {
            storeFile = file("signing/netstrazh.jks")
            storePassword = "netstrazh"
            keyAlias = "netstrazh"
            keyPassword = "netstrazh"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("shared")
        }
        debug {
            signingConfig = signingConfigs.getByName("shared")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    lint {
        abortOnError = false
        checkReleaseBuilds = false
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}
