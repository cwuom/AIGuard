package com.aiguard.app

import com.aiguard.core.DaemonPaths
import com.aiguard.core.FirewallBuilder
import com.aiguard.daemon.DaemonMain
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** 开机脚本、看门狗、安装/卸载脚本与 Kotlin 代码之间的约定：任一边改名都会让守护进程起不来或卸不干净 */
class ScriptsContractTest {
    private fun script(name: String) = File("src/main/assets/scripts/$name").readText()

    @Test
    fun scriptsUseSamePathsAsDaemon() {
        for (name in listOf("service.sh", "watchdog.sh", "install.sh", "uninstall.sh")) {
            val s = script(name)
            assertTrue("$name 必须用 ${DaemonPaths.ROOT}", s.contains("DIR=${DaemonPaths.ROOT}"))
            assertTrue("$name 需要 shebang", s.startsWith("#!/system/bin/sh\n"))
        }
        assertTrue(script("install.sh").contains("/data/adb/service.d/aiguard.sh"))
        assertEquals("/data/adb/service.d/aiguard.sh", DaemonPaths.SERVICE_SCRIPT)
        for ((file, path) in listOf("aiguard.apk" to DaemonPaths.APK, "ipc_token" to DaemonPaths.TOKEN, "app_uid" to DaemonPaths.APP_UID, "uninstalling" to DaemonPaths.UNINSTALL_FLAG)) {
            assertEquals("${DaemonPaths.ROOT}/$file", path)
            assertTrue("install/uninstall 必须处理 $file", (script("install.sh") + script("uninstall.sh")).contains(file))
        }
    }

    @Test
    fun watchdogLaunchesTheRealEntryPoint() {
        val w = script("watchdog.sh")
        assertTrue(w.contains(DaemonMain::class.java.name))
        assertTrue("进程名要和安装/卸载脚本识别的一致", w.contains("--nice-name=aiguardd"))
        assertTrue(script("install.sh").contains("^aiguardd"))
        assertTrue(script("uninstall.sh").contains("aiguardd*"))
        assertTrue(script("uninstall.sh").contains("--teardown"))
    }

    @Test
    fun uninstallFallbackRemovesEveryChain() {
        val u = script("uninstall.sh")
        for (c in listOf(FirewallBuilder.CHAIN, FirewallBuilder.CHAIN6, FirewallBuilder.DNS_CHAIN, FirewallBuilder.CN_CHAIN)) {
            assertTrue("卸载兜底必须拆掉 $c", u.contains(c))
        }
    }

    @Test
    fun installerOutputMarkersMatchApp() {
        assertTrue(script("install.sh").contains("AIGUARD_INSTALL_OK"))
        assertTrue(script("uninstall.sh").contains("AIGUARD_UNINSTALL_OK"))
    }
}
