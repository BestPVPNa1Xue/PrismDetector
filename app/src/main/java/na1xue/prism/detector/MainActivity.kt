/* Based on supplied Ruru MainActivity.kt (Nullptr & byxiaorun), Apache-2.0.
 * Preserves Scaffold, top bar, About FAB and dialog layout; replaces detector startup.
 * Extra actions use the same Material3 dialog/text-button components and theme. */
package na1xue.prism.detector

import android.content.ClipData
import android.content.ActivityNotFoundException
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.layout.displayCutoutPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.EmojiObjects
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import icu.nullptr.applistdetector.MainPage
import icu.nullptr.applistdetector.theme.MyTheme

class MainActivity : ComponentActivity() {
    @Deprecated("Platform result callback retained for Ruru's original dependency versions")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        val uri = data?.data
        if (requestCode == 42 && resultCode == RESULT_OK && uri != null) try {
            contentResolver.openOutputStream(uri)?.use { it.write(DetectorStore.report.toByteArray(Charsets.UTF_8)) }
                ?: error("无法打开保存位置")
            Toast.makeText(this, "报告已保存", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) { Toast.makeText(this, "保存失败：${e.message}", Toast.LENGTH_LONG).show() }
    }

    @OptIn(ExperimentalMaterial3Api::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Own the insets explicitly, including Android 15's enforced edge-to-edge.
        WindowCompat.setDecorFitsSystemWindows(window, false)
        WindowCompat.getInsetsController(window, window.decorView)
            .show(WindowInsetsCompat.Type.systemBars())
        setContent {
            MyTheme {
                var showDialog by remember { mutableStateOf(false) }
                var showSettings by remember { mutableStateOf(false) }
                var showExport by remember { mutableStateOf(false) }
                if (showDialog) AboutDialog(
                    onDismiss = { showDialog = false },
                    onScan = { showDialog = false; DetectorStore.scan(this) },
                    onSettings = { showDialog = false; showSettings = true },
                    onExport = { showDialog = false; showExport = true }
                )
                if (showSettings) SettingsDialog { showSettings = false }
                if (showExport) ExportDialog(
                    onDismiss = { showExport = false },
                    onSave = {
                        showExport = false
                        startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT)
                            .addCategory(Intent.CATEGORY_OPENABLE).setType("application/json")
                            .putExtra(Intent.EXTRA_TITLE, "PrismDetector-report.json"), 42)
                    },
                    onShare = {
                        showExport = false
                        val uri = Uri.parse("content://na1xue.prism.detector.reports/report.json")
                        val intent = Intent(Intent.ACTION_SEND).setType("application/json")
                            .putExtra(Intent.EXTRA_STREAM, uri)
                            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        intent.clipData = ClipData.newRawUri("PrismDetector", uri)
                        startActivity(Intent.createChooser(intent, "分享检测报告"))
                    }
                )
                Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    Scaffold(
                        modifier = Modifier.systemBarsPadding().displayCutoutPadding(),
                        topBar = { MainTopBar() },
                        floatingActionButton = { MainFab { showDialog = true } }
                    ) { innerPadding -> MainPage(Modifier.padding(innerPadding)) }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MainTopBar() {
    CenterAlignedTopAppBar(
        title = { Text(stringResource(R.string.app_name) + " V${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})") }
    )
}

@Composable
private fun MainFab(onClick: () -> Unit) {
    ExtendedFloatingActionButton(
        icon = { Icon(Icons.Outlined.EmojiObjects, stringResource(R.string.about)) },
        text = { Text(stringResource(R.string.about)) },
        onClick = onClick
    )
}

@Composable
private fun AboutDialog(onDismiss: () -> Unit, onScan: () -> Unit, onSettings: () -> Unit, onExport: () -> Unit) {
    val context = LocalContext.current
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(android.R.string.ok)) } },
        title = { Text(stringResource(R.string.about)) },
        text = {
            Column(horizontalAlignment = Alignment.Start, modifier = Modifier.verticalScroll(rememberScrollState())) {
                CompositionLocalProvider(LocalTextStyle provides MaterialTheme.typography.bodyLarge) {
                    Text(stringResource(R.string.app_name) + " V${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
                    Text("UI：Ruru · Nullptr & byxiaorun")
                    Text("Apache License 2.0")
                }
                Spacer(Modifier.height(10.dp))
                TextButton(onClick = {
                    try {
                        context.startActivity(Intent(Intent.ACTION_VIEW,
                            Uri.parse("https://github.com/BestPVPNa1Xue/PrismDetector")))
                    } catch (e: ActivityNotFoundException) {
                        Toast.makeText(context, "没有可打开链接的浏览器", Toast.LENGTH_LONG).show()
                    }
                }) { Text("GitHub 开源仓库 · BestPVPNa1Xue/PrismDetector") }
                Text("进程项检测本应用；Minecraft 安装包与证书单独查询。设备 ID、日志等信息项仅作展示。")
                TextButton(onClick = onScan, enabled = !DetectorStore.scanning) { Text(if (DetectorStore.scanning) "检测中…" else "重新检测") }
                TextButton(onClick = onSettings) { Text("检测设置") }
                TextButton(onClick = onExport, enabled = DetectorStore.report.isNotEmpty()) { Text("导出检测报告") }
            }
        }
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SettingsDialog(onDismiss: () -> Unit) {
    val context = LocalContext.current
    val prefs = remember { context.getSharedPreferences("options", Context.MODE_PRIVATE) }
    var online by remember { mutableStateOf(prefs.getBoolean("network", true)) }
    var active by remember { mutableStateOf(prefs.getBoolean("active", false)) }
    var classes by remember { mutableStateOf(prefs.getString("classes", "") ?: "") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("检测设置") },
        confirmButton = { TextButton(onClick = {
            prefs.edit().putBoolean("network", online).putBoolean("active", active).putString("classes", classes).apply()
            onDismiss()
        }) { Text("保存") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text("网络时间校对")
                Switch(checked = online, onCheckedChange = { online = it })
                Spacer(Modifier.height(10.dp))
                Text("ARM64 主动 SIGSYS 探测")
                Switch(checked = active, onCheckedChange = { active = it })
                Text("仅原分支需要时执行。默认关闭，临时替换并恢复本进程信号处理器。")
                Spacer(Modifier.height(10.dp))
                OutlinedTextField(value = classes, onValueChange = { classes = it },
                    label = { Text("JNI 类名单，每行一个") }, placeholder = { Text("java/lang/String") }, maxLines = 6)
                Text("保存后重新检测生效。")
            }
        }
    )
}

@Composable
private fun ExportDialog(onDismiss: () -> Unit, onSave: () -> Unit, onShare: () -> Unit) {
    val context = LocalContext.current
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("导出检测报告") },
        confirmButton = { TextButton(onClick = onDismiss) { Text("关闭") } },
        text = {
            Column {
                TextButton(onClick = onSave) { Text("保存 JSON 文件") }
                TextButton(onClick = onShare) { Text("分享 JSON 报告") }
                TextButton(onClick = {
                    (context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager)
                        .setPrimaryClip(ClipData.newPlainText("PrismDetector", DetectorStore.report))
                    Toast.makeText(context, "已复制", Toast.LENGTH_SHORT).show()
                    onDismiss()
                }) { Text("复制完整报告") }
            }
        }
    )
}

// Ruru's original resultMap uses this tiny string adapter at initialization.
fun gettext(key: String): Array<String> = arrayOf(when (key) {
    "not_found" -> "未发现"
    "method" -> "不可用 / 未执行"
    "suspicious" -> "可疑"
    "found" -> "危险"
    else -> key
})
