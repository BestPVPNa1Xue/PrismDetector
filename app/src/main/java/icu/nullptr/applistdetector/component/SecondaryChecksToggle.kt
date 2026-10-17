/* Based on Ruru's CheckCard Surface, spacing, arrow and spring animation. Apache-2.0. */
package icu.nullptr.applistdetector.component

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp

@Composable
fun SecondaryChecksToggle(expanded: Boolean, onClick: () -> Unit) {
    val rotation by animateFloatAsState(if (expanded) 180f else 0f)
    Surface(
        modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp)
            .clip(RoundedCornerShape(16.dp)).clickable(role = Role.Button, onClick = onClick),
        color = MaterialTheme.colorScheme.primaryContainer,
        tonalElevation = 2.dp
    ) {
        Row(Modifier.fillMaxWidth().padding(16.dp)) {
            Text(if (expanded) "隐藏次要检测项" else "显示次要检测项",
                modifier = Modifier.weight(1f), style = MaterialTheme.typography.titleMedium)
            Icon(Icons.Filled.ArrowDropDown, null, Modifier.rotate(rotation))
        }
    }
}
