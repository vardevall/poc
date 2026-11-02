package dev.vardevall

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.lifecycle.lifecycleScope
import dev.vardevall.ui.VardevallApp
import dev.vardevall.ui.VardevallTheme
import kotlinx.coroutines.launch

/** The single activity: the screens of the app, and the entry point of an interface file shared or opened with it. */
class MainActivity : ComponentActivity() {
    private val model: AppViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent { VardevallTheme { VardevallApp(model) } }
        if (savedInstanceState == null) receive(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        receive(intent)
    }

    /** An interface file from the share sheet (`SEND`) or from another app's "open with" (`VIEW`). */
    private fun receive(intent: Intent?) {
        val shared: Uri? = when (intent?.action) {
            Intent.ACTION_SEND -> if (android.os.Build.VERSION.SDK_INT >= 33) {
                intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
            } else {
                @Suppress("DEPRECATION")
                intent.getParcelableExtra(Intent.EXTRA_STREAM)
            }
            Intent.ACTION_VIEW -> intent.data
            else -> null
        }
        val sharedText = if (intent?.action == Intent.ACTION_SEND) intent.getStringExtra(Intent.EXTRA_TEXT) else null
        lifecycleScope.launch {
            val text = shared?.let { model.readText(it) } ?: sharedText
            if (text != null) model.offerImport(text)
        }
    }
}
