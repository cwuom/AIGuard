import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

/** 把 Vendor/ 里的内核与规则库打包进 assets；缺文件时直接失败，不出没有内核的 APK */
abstract class SyncVendorAssets : DefaultTask() {
    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val vendorDir: DirectoryProperty

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun sync() {
        val vendor = vendorDir.get().asFile
        val out = outputDir.get().asFile
        out.deleteRecursively()
        val core = File(vendor, "android/mihomo")
        require(core.isFile) { "缺少 ${core.path}，先运行 android/scripts/fetch-core.sh" }
        core.copyTo(File(out, "core/mihomo"))
        File(vendor, "android/VERSION").takeIf { it.isFile }?.copyTo(File(out, "core/VERSION"))
        for (name in listOf("geosite-cn.mrs", "geoip-cn.mrs", "geosite-anthropic.mrs", "geosite-category-ntp.mrs", "cn4.txt")) {
            val f = File(vendor, "rules/$name")
            require(f.isFile) { "缺少 ${f.path}，先运行仓库根目录的 scripts/fetch-core.sh" }
            f.copyTo(File(out, "rules/$name"))
        }
    }
}

val syncVendorAssets = tasks.register<SyncVendorAssets>("syncVendorAssets") {
    vendorDir.set(rootProject.layout.projectDirectory.dir("../Vendor"))
    outputDir.set(layout.buildDirectory.dir("generated/vendorAssets"))
}

android {
    namespace = "com.aiguard.app"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.aiguard.app"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "1.0.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // 与 macOS 版一致：本机签名，换机器构建需要卸载重装
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources.excludes += setOf("META-INF/*.version", "META-INF/**/LICENSE*", "kotlin/**", "DebugProbesKt.bin")
    }

    lint {
        warningsAsErrors = true
        abortOnError = true
        // 守护进程以 root 运行 iptables/am 等系统命令，这些检查针对普通 App 场景
        disable += setOf("SdCardPath", "GradleDependency", "NewerVersionAvailable", "AndroidGradlePluginVersion", "OldTargetApi")
    }
}

androidComponents {
    onVariants { variant ->
        variant.sources.assets?.addGeneratedSourceDirectory(syncVendorAssets, SyncVendorAssets::outputDir)
    }
}

kotlin {
    jvmToolchain(17)
    compilerOptions {
        allWarningsAsErrors.set(true)
    }
}

dependencies {
    implementation(project(":core"))
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.foundation)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons)
    implementation(libs.androidx.compose.ui.tooling.preview)
    debugImplementation(libs.androidx.compose.ui.tooling)
    testImplementation(libs.junit)
}
