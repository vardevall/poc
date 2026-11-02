package dev.vardevall.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.vardevall.AppViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** What the check of the text says. */
sealed interface Check {
    data object Pending : Check

    data class Valid(val text: String) : Check

    data class Invalid(val text: String) : Check
}

/** How long the text rests before it is checked. */
const val CHECK_DELAY_MS = 800L

/**
 * The state of the editor: the saved networks do not change until it is saved. [original] is the
 * text it opens on and [isNew] says the network is not added yet.
 */
class EditorState(val originalName: String, val original: String, val isNew: Boolean) {
    var name by mutableStateOf(originalName)
    var text by mutableStateOf(original)
    var check: Check by mutableStateOf(Check.Pending)

    /** Whether the check of [text] is due at once rather than after the delay. */
    var immediate by mutableStateOf(true)

    val isInvalid: Boolean get() = check is Check.Invalid

    val canSave: Boolean
        get() = !isInvalid && name.isNotEmpty() && (isNew || text != original || name != originalName)

    fun edit(new: String) {
        if (new == text) return
        text = new
        immediate = false
        check = Check.Pending
    }

    fun replace(new: String) {
        text = new
        immediate = true
        check = Check.Pending
    }
}

/**
 * The interface file of a network: the text is checked while it is typed, with the import
 * buttons below; [failure] is why the last save did not succeed. Save and Cancel are in the
 * top bar of the caller.
 */
@Composable
fun EditorScreen(
    vm: AppViewModel,
    editor: EditorState,
    failure: String?,
) {
    val scope = rememberCoroutineScope()
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) scope.launch { vm.readText(uri)?.let(editor::replace) }
    }
    LaunchedEffect(editor.text, editor.immediate) {
        if (!editor.immediate) delay(CHECK_DELAY_MS)
        editor.check = vm.validate(editor.text).fold(
            onSuccess = { s ->
                val n = s.peers.size
                Check.Valid("Valid: ${s.domain}, $n ${if (n == 1) "device" else "devices"}")
            },
            onFailure = { Check.Invalid(it.message ?: "The text is not valid.") },
        )
    }
    Column(Modifier.verticalScroll(rememberScrollState()).imePadding().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        OutlinedTextField(
            value = editor.name,
            onValueChange = { editor.name = it },
            label = { Text("Name") },
            placeholder = { Text("home") },
            supportingText = {
                Text(
                    if (editor.isNew) "Lowercase letters, digits and dashes."
                    else "Lowercase letters, digits and dashes. A new name applies when you connect again.",
                )
            },
            singleLine = true,
            keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false),
            modifier = Modifier.fillMaxWidth().testTag("name"),
        )
        OutlinedTextField(
            value = editor.text,
            onValueChange = editor::edit,
            label = { Text("Interface file") },
            textStyle = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 12.sp),
            keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false),
            isError = editor.isInvalid,
            supportingText = {
                when (val check = editor.check) {
                    Check.Pending -> Text("Checking…")
                    is Check.Valid -> Text(check.text)
                    is Check.Invalid -> Text(check.text, color = MaterialTheme.colorScheme.error)
                }
            },
            modifier = Modifier.fillMaxWidth().heightIn(min = 260.dp).testTag("text"),
        )
        if (failure != null) Text(failure, color = MaterialTheme.colorScheme.error)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilledTonalButton(onClick = { scope.launch { editor.replace(vm.newConfig()) } }) { Text("New keys") }
            OutlinedButton(onClick = { picker.launch(arrayOf("*/*")) }) { Text("Import") }
        }
    }
}
