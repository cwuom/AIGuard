package com.aiguard.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import com.aiguard.app.ui.AIGuardTheme
import com.aiguard.app.ui.AppRoot

/** 界面只是遥控器：真正的防护在 root 守护进程里，这里被系统回收也不影响 */
class MainActivity : ComponentActivity() {
    private val vm: GuardViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent {
            AIGuardTheme {
                AppRoot(vm)
            }
        }
    }

    override fun onStart() {
        super.onStart()
        vm.setForeground(true)
    }

    override fun onStop() {
        vm.setForeground(false)
        super.onStop()
    }
}
