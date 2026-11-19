import com.android.build.api.artifact.SingleArtifact
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.ksp)
    alias(libs.plugins.hilt)
    alias(libs.plugins.detekt)
}

// Optional release signing: provide keystore.properties (never committed) with
// storeFile, storePassword, keyAlias, keyPassword. Without it the release APK is unsigned.
val keystoreProps = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

android {
    namespace = "com.adshield"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.adshield"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "1.0.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        if (keystoreProps.containsKey("storeFile")) {
            create("release") {
                storeFile = rootProject.file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfigs.findByName("release")?.let { signingConfig = it }
        }
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    sourceSets {
        getByName("main").java.srcDir("src/main/kotlin")
        getByName("test").java.srcDir("src/test/kotlin")
        getByName("androidTest").java.srcDir("src/androidTest/kotlin")
    }

    lint {
        abortOnError = true
        checkReleaseBuilds = true
        warningsAsErrors = false
        htmlReport = true
        xmlReport = true
        sarifReport = true
        // The adaptive icon must live in mipmap-anydpi-v26 for AAPT2 to register it.
        disable += "ObsoleteSdkInt"
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }

    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }
}

kotlin {
    jvmToolchain(17)
}

/**
 * Privacy gate on the *merged* manifest (what actually ships, including permissions that libraries inject
 * through manifest merging). The build fails if anything outside the approved set appears.
 */
abstract class VerifyPermissionsTask : DefaultTask() {
    @get:InputFile
    abstract val manifest: RegularFileProperty

    @get:Input
    abstract val allowed: SetProperty<String>

    @TaskAction
    fun verify() {
        val declared = Regex("""<uses-permission(?:-sdk-\d+)?\s+[^>]*?android:name="([^"]+)"""")
            .findAll(manifest.get().asFile.readText()).map { it.groupValues[1] }.toSet()
        val unexpected = declared - allowed.get()
        check(unexpected.isEmpty()) { "Merged manifest requests unapproved permissions: $unexpected" }
        check("android.permission.QUERY_ALL_PACKAGES" !in declared)
        logger.lifecycle("Merged manifest permissions OK: ${declared.sorted()}")
    }
}

androidComponents {
    onVariants { variant ->
        val name = variant.name.replaceFirstChar { it.uppercase() }
        val verify = tasks.register<VerifyPermissionsTask>("verify${name}Permissions") {
            manifest.set(variant.artifacts.get(SingleArtifact.MERGED_MANIFEST))
            allowed.set(
                setOf(
                    "android.permission.INTERNET",
                    "android.permission.ACCESS_NETWORK_STATE",
                    "android.permission.FOREGROUND_SERVICE",
                    "android.permission.FOREGROUND_SERVICE_SPECIAL_USE",
                    "android.permission.POST_NOTIFICATIONS",
                    // Internal signature permission that androidx.core adds for non-exported dynamic receivers.
                    "com.adshield.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION",
                    "com.adshield.debug.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION",
                ),
            )
        }
        tasks.matching { it.name == "check" || it.name == "assemble$name" }.configureEach { dependsOn(verify) }
    }
}

ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
    arg("room.generateKotlin", "true")
}

detekt {
    buildUponDefaultConfig = true
    config.setFrom(rootProject.file("config/detekt/detekt.yml"))
    source.setFrom("src/main/kotlin", "src/test/kotlin")
    parallel = true
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.core.splashscreen)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime)
    implementation(libs.androidx.lifecycle.viewmodel)
    implementation(libs.androidx.navigation.compose)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.icons.extended)
    debugImplementation(libs.androidx.compose.ui.tooling)

    implementation(libs.androidx.datastore.preferences)
    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    ksp(libs.androidx.room.compiler)

    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)
    implementation(libs.hilt.navigation.compose)

    implementation(libs.kotlinx.coroutines.android)

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)

    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.room.testing)
    androidTestImplementation(libs.kotlinx.coroutines.test)
}
