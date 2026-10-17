/* Derived from the supplied Ruru 1.1.1 MainPage.kt, Apache-2.0.
 * Modified: replace detector scheduling/data with Prism snapshots; retain the original UI tree. */
package icu.nullptr.applistdetector

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.key
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import icu.nullptr.applistdetector.component.CheckCard
import icu.nullptr.applistdetector.component.IconHintCard
import icu.nullptr.applistdetector.component.SecondaryChecksToggle
import na1xue.prism.detector.DetectorStore

private val primaryChecks = setOf("minecraft_size", "minecraft_certificate", "network_time",
    "accessibility", "input_methods", "keymapper_package", "identity")

@Composable
fun MainPage(modifier: Modifier) {
    val context = LocalContext.current
    var showSecondary by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(Unit) { DetectorStore.ensureScan(context) }
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        IconHintCard()
        if (DetectorStore.items.isEmpty() && DetectorStore.failure.isEmpty()) {
            CheckCard("正在检测…", null, mutableListOf())
        }
        if (DetectorStore.failure.isNotEmpty()) {
            CheckCard("检测未完成", IDetector.Result.METHOD_UNAVAILABLE,
                mutableListOf(DetectorStore.failure to IDetector.Result.METHOD_UNAVAILABLE))
        }
        DetectorStore.items.filter { it.id in primaryChecks }.forEach { item ->
            key(item.id) {
                CheckCard(
                    title = item.title,
                    result = if (DetectorStore.scanning) null else item.result,
                    detail = item.detail
                )
            }
        }
        if (DetectorStore.items.any { it.id !in primaryChecks }) {
            SecondaryChecksToggle(showSecondary) { showSecondary = !showSecondary }
            AnimatedVisibility(
                visible = showSecondary,
                enter = expandVertically(expandFrom = Alignment.Top,
                    animationSpec = spring(stiffness = Spring.StiffnessLow)),
                exit = shrinkVertically(shrinkTowards = Alignment.Top,
                    animationSpec = spring(stiffness = Spring.StiffnessLow))
            ) {
                Column {
                    DetectorStore.items.filter { it.id !in primaryChecks }.forEach { item ->
                        key(item.id) {
                            CheckCard(item.title, if (DetectorStore.scanning) null else item.result, item.detail)
                        }
                    }
                }
            }
        }
        // Scrollable space lets the last card clear the original 56dp About FAB.
        Spacer(Modifier.height(112.dp))
    }
}
