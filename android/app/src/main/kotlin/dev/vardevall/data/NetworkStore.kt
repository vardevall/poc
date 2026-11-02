package dev.vardevall.data

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.core.content.edit
import dev.vardevall.model.ExitChoice
import dev.vardevall.model.NetworkConfig
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * AES-GCM with a key that never leaves the Android Keystore. The result is the 12-byte IV
 * followed by the ciphertext.
 */
class SecretBox(private val alias: String = "vardevall.networks") {
    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    fun seal(plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, key()) }
        return cipher.iv + cipher.doFinal(plain)
    }

    fun open(sealed: ByteArray): ByteArray {
        require(sealed.size > IV_BYTES) { "too short" }
        val cipher = Cipher.getInstance(TRANSFORM).apply {
            init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG_BITS, sealed, 0, IV_BYTES))
        }
        return cipher.doFinal(sealed, IV_BYTES, sealed.size - IV_BYTES)
    }

    private companion object {
        const val TRANSFORM = "AES/GCM/NoPadding"
        const val IV_BYTES = 12
        const val TAG_BITS = 128
    }
}

/**
 * The interface files of the networks, in the order the user gave them. They hold secrets, so the
 * file in the app's private storage is encrypted with a key of the Keystore; nothing of it goes
 * to logs, intents or backups.
 */
class NetworkStore(context: Context, private val box: SecretBox = SecretBox()) {
    @Serializable
    private data class Entry(val name: String, val text: String)

    @Serializable
    private data class Document(val networks: List<Entry> = emptyList())

    private val file = File(context.applicationContext.filesDir, "networks.bin")

    @Synchronized
    fun load(): List<NetworkConfig> {
        if (!file.exists()) return emptyList()
        val plain = box.open(file.readBytes())
        return Json.decodeFromString<Document>(plain.decodeToString()).networks.map { NetworkConfig(it.name, it.text) }
    }

    @Synchronized
    fun save(networks: List<NetworkConfig>) {
        if (networks.isEmpty()) {
            file.delete()
            return
        }
        val plain = Json.encodeToString(Document(networks.map { Entry(it.name, it.text) })).encodeToByteArray()
        val tmp = File(file.parentFile, "networks.bin.tmp")
        tmp.writeBytes(box.seal(plain))
        check(tmp.renameTo(file)) { "the networks could not be saved" }
    }
}

/**
 * What is not secret: the exit the user chose and the offers each network remembers (the public
 * keys of exits and their sites).
 */
class Settings(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences("settings", Context.MODE_PRIVATE)

    var exit: ExitChoice?
        get() = prefs.getString("exit.network", null)?.let { ExitChoice(it, prefs.getString("exit.site", null)) }
        set(value) {
            prefs.edit {
                putString("exit.network", value?.network)
                putString("exit.site", value?.site)
            }
        }

    fun exits(network: String): String? = prefs.getString("exits.$network", null)

    fun setExits(network: String, offersJson: String) {
        prefs.edit { putString("exits.$network", offersJson) }
    }

    fun forgetExits(network: String) {
        prefs.edit { remove("exits.$network") }
    }
}
