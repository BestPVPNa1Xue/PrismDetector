package na1xue.prism.detector

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import icu.nullptr.applistdetector.Detail
import icu.nullptr.applistdetector.IDetector
import kotlinx.coroutines.*
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream

data class CheckSnapshot(val id: String, val title: String, val result: IDetector.Result, val detail: Detail)

/** One application-scoped scan; composing/rotating the UI never repeats native work. */
object DetectorStore {
    val items = mutableStateListOf<CheckSnapshot>()
    var scanning by mutableStateOf(false)
        private set
    var failure by mutableStateOf("")
        private set
    var report by mutableStateOf("")
        private set
    private var initialized = false
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    private fun result(state: String) = when (state) {
        "danger" -> IDetector.Result.FOUND
        "suspicious", "warn" -> IDetector.Result.SUSPICIOUS
        "unknown", "na" -> IDetector.Result.METHOD_UNAVAILABLE
        else -> IDetector.Result.NOT_FOUND
    }

    private fun parse(json: String): List<CheckSnapshot> {
        val values = JSONObject(json).getJSONArray("items")
        return (0 until values.length()).map { n ->
            val item = values.getJSONObject(n)
            val state = result(item.getString("state"))
            val details: Detail = mutableListOf(item.getString("summary") to state)
            val rows = item.optJSONArray("rows")
            if (rows != null) for (i in 0 until rows.length()) {
                val row = rows.getJSONObject(i)
                details.add(row.getString("text") to result(row.getString("state")))
            }
            details.add(("来源：" + item.getString("origin") + "\n" + item.getString("details")) to IDetector.Result.NOT_FOUND)
            CheckSnapshot(item.getString("id"), item.getString("title"), state, details)
        }
    }

    fun ensureScan(context: Context) {
        if (initialized) return
        initialized = true
        scan(context)
    }

    fun scan(context: Context) {
        if (scanning) return
        scanning = true
        failure = ""
        val app = context.applicationContext
        val prefs = app.getSharedPreferences("options", Context.MODE_PRIVATE)
        val classes = prefs.getString("classes", "") ?: ""
        val active = prefs.getBoolean("active", false)
        val online = prefs.getBoolean("network", true)
        scope.launch {
            try {
                val (json, snapshot) = withContext(Dispatchers.IO) {
                    val json = NativeBridge.nativeScan(app, classes, active, online)
                    val snapshot = parse(json)
                    val temporary = File(app.filesDir, "report.tmp")
                    FileOutputStream(temporary).use { out ->
                        out.write(json.toByteArray(Charsets.UTF_8))
                        out.fd.sync()
                    }
                    check(temporary.renameTo(File(app.filesDir, "report.json"))) { "报告保存失败" }
                    json to snapshot
                }
                report = json
                items.clear()
                items.addAll(snapshot)
            } catch (e: Exception) {
                failure = e.message ?: e.javaClass.simpleName
            } catch (e: LinkageError) {
                failure = "原生库加载失败：${e.message}"
            } finally {
                scanning = false
            }
        }
    }
}
