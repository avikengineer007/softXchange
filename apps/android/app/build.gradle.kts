plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.softxchange"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.softxchange"
        minSdk = 26    // Oreo — required for Filament and our Tier C floor
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }

    // 3D Asset budget check — runs before compilation
    // Mirrors the web-side npm run check:assets
    tasks.register<Exec>("checkAndroidAssets") {
        group = "verification"
        description = "Verify all .glb assets in res/raw are within the byte-size budget"
        commandLine("bash", "scripts/check-android-assets.sh")
    }
    tasks.named("preBuild") {
        dependsOn("checkAndroidAssets")
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.navigation.compose)

    // Filament — Google's real-time PBR renderer + glTF loader
    implementation(libs.filament.android)
    implementation(libs.gltfio.android)
    implementation(libs.filament.utils.android)

    // Coroutines for async glTF loading
    implementation(libs.kotlinx.coroutines.android)

    debugImplementation(libs.androidx.ui.tooling)
    debugImplementation(libs.androidx.ui.test.manifest)
}
