package dev.bhejo.app

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.OpenableColumns
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.Date
import java.util.Locale
import kotlin.concurrent.thread

class MainActivity : Activity() {

    private lateinit var identity: Identity
    private var discovery: Discovery? = null
    private var receiver: Receiver? = null

    private lateinit var statusView: TextView
    private lateinit var toggleButton: Button
    private lateinit var pinInput: EditText
    private lateinit var pickedLabel: TextView
    private lateinit var peersBox: LinearLayout
    private lateinit var logView: TextView

    private val picked = ArrayList<PickedFile>()
    private val discovered = ArrayList<Discovery.Peer>()
    private val manual = ArrayList<Discovery.Peer>()
    private val ui = Handler(Looper.getMainLooper())
    private var pending: AlertDialog? = null

    @Volatile
    private var running = false

    @Volatile
    private var currentPin: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        identity = Identity.load(this)
        loadManualPeers()
        setContentView(buildUi())
        log("this device: ${identity.alias}")
        log("fingerprint: ${Identity.pretty(identity.fingerprint)}")
        startReceiving()
    }

    override fun onDestroy() {
        try {
            pending?.dismiss()
        } catch (_: Exception) {
        }
        stopReceiving()
        super.onDestroy()
    }

    // ---- view -------------------------------------------------------------

    private fun buildUi(): View {
        val scroll = ScrollView(this).apply { setBackgroundColor(PAPER) }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(22), dp(28), dp(22), dp(36))
        }
        scroll.addView(root)

        root.addView(
            TextView(this).apply {
                text = "bhejo"
                textSize = 32f
                typeface = Typeface.create("sans-serif", Typeface.BOLD)
                setTextColor(INK)
                letterSpacing = -0.02f
            },
        )

        root.addView(
            body("Send files to the computer next to you. Same Wi-Fi, no cloud, no account.")
                .apply { setPadding(0, dp(6), 0, dp(18)) },
        )

        statusView = TextView(this).apply {
            textSize = 14f
            setTextColor(INK)
            setBackground(rounded(SOFT, 14))
            setPadding(dp(16), dp(14), dp(16), dp(14))
        }
        root.addView(statusView)

        toggleButton = Button(this).apply {
            text = "Stop receiving"
            isAllCaps = false
            textSize = 15f
            setTextColor(Color.WHITE)
            backgroundTintList = ColorStateList.valueOf(INK)
            setOnClickListener { if (running) stopReceiving() else startReceiving() }
        }
        root.addView(toggleButton, LinearLayout.LayoutParams(MATCH, dp(52)).apply { topMargin = dp(12) })

        root.addView(section("PIN"))
        pinInput = EditText(this).apply {
            hint = "Optional shared PIN"
            inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
            textSize = 15f
            setSingleLine(true)
            typeface = Typeface.DEFAULT
            setTextColor(INK)
            setHintTextColor(INK2)
            setBackground(rounded(SOFT, 14))
            setPadding(dp(16), dp(12), dp(16), dp(12))
            addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                    val value = s?.toString()?.trim().orEmpty()
                    currentPin = if (value.isEmpty()) null else value
                    receiver?.pin = currentPin
                }

                override fun afterTextChanged(s: Editable?) = Unit
            })
        }
        root.addView(pinInput)
        root.addView(
            body("Used for incoming transfers, and sent when the computer asks for one.")
                .apply { setPadding(0, dp(8), 0, 0) },
        )

        root.addView(section("FILES"))
        root.addView(
            primary("Choose files") { pickFiles() },
            LinearLayout.LayoutParams(MATCH, dp(52)),
        )
        pickedLabel = body("No files chosen.").apply { setPadding(0, dp(10), 0, 0) }
        root.addView(pickedLabel)

        root.addView(section("NEARBY"))
        peersBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        root.addView(peersBox)
        root.addView(
            secondary("Add a computer by IP") { addByIp() },
            LinearLayout.LayoutParams(MATCH, dp(46)).apply { topMargin = dp(6) },
        )
        renderPeers()

        root.addView(section("ACTIVITY"))
        logView = TextView(this).apply {
            textSize = 12f
            typeface = Typeface.MONOSPACE
            setTextColor(INK)
            setBackground(rounded(SOFT, 14))
            setPadding(dp(14), dp(12), dp(14), dp(12))
            setTextIsSelectable(true)
        }
        root.addView(logView)

        return scroll
    }

    private fun section(title: String): TextView = TextView(this).apply {
        text = title
        textSize = 11f
        setTextColor(INK2)
        letterSpacing = 0.12f
        setPadding(0, dp(28), 0, dp(10))
    }

    private fun body(text: String): TextView = TextView(this).apply {
        this.text = text
        textSize = 15f
        setTextColor(INK2)
        setLineSpacing(dp(3).toFloat(), 1f)
    }

    private fun primary(label: String, onClick: () -> Unit): Button = Button(this).apply {
        text = label
        isAllCaps = false
        textSize = 15f
        setTextColor(Color.WHITE)
        backgroundTintList = ColorStateList.valueOf(INK)
        setOnClickListener { onClick() }
    }

    private fun secondary(label: String, onClick: () -> Unit): Button = Button(this).apply {
        text = label
        isAllCaps = false
        textSize = 14f
        setTextColor(INK)
        background = roundedWithStroke(PAPER, LINE, 14)
        setOnClickListener { onClick() }
    }

    // ---- receiving --------------------------------------------------------

    private fun startReceiving() {
        if (running) return
        try {
            val rec = Receiver(
                context = this,
                identity = identity,
                onIncoming = { transfer -> ui.post { askIncoming(transfer) } },
                onLog = { line -> ui.post { log(line) } },
            )
            rec.pin = currentPin
            rec.start()
            receiver = rec
            running = true

            val disc = Discovery(
                identity = identity,
                serverPort = { rec.server.port },
                onPeers = { list ->
                    ui.post {
                        discovered.clear()
                        discovered.addAll(list)
                        renderPeers()
                    }
                },
                onLog = { line -> ui.post { log(line) } },
            )
            disc.start(this)
            discovery = disc

            statusView.text = "Receiving on port ${rec.server.port}. Keep this screen open."
            toggleButton.text = "Stop receiving"
            renderPeers()
        } catch (e: Exception) {
            running = false
            statusView.text = "Could not start: ${e.message}"
            log("start failed: ${e.message}")
        }
    }

    private fun stopReceiving() {
        if (!running) return
        running = false
        try {
            discovery?.stop()
        } catch (_: Exception) {
        }
        discovery = null
        try {
            receiver?.stop()
        } catch (_: Exception) {
        }
        receiver = null
        statusView.text = "Not receiving."
        toggleButton.text = "Start receiving"
        renderPeers()
    }

    private fun askIncoming(transfer: IncomingTransfer) {
        try {
            pending?.dismiss()
        } catch (_: Exception) {
        }
        val names = transfer.files.take(3).joinToString(", ") { it.fileName }
        val extra = if (transfer.files.size > 3) " and ${transfer.files.size - 3} more" else ""
        val dialog = AlertDialog.Builder(this)
            .setTitle("Incoming from ${transfer.alias}")
            .setMessage("$names$extra\n\n${formatBytes(transfer.totalBytes)}\n\nSaved to Downloads/Bhejo.")
            .setPositiveButton("Accept") { _, _ ->
                transfer.accept()
                log("accepted from ${transfer.alias}")
            }
            .setNegativeButton("Decline") { _, _ ->
                transfer.decline()
                log("declined ${transfer.alias}")
            }
            .setOnCancelListener { transfer.decline() }
            .create()
        dialog.setCanceledOnTouchOutside(false)
        dialog.show()
        pending = dialog
    }

    // ---- peers ------------------------------------------------------------

    private fun renderPeers() {
        peersBox.removeAllViews()

        val seen = HashSet<String>()
        val all = ArrayList<Discovery.Peer>()
        for (peer in manual) if (seen.add(peer.fingerprint)) all.add(peer)
        for (peer in discovered) if (seen.add(peer.fingerprint)) all.add(peer)

        if (all.isEmpty()) {
            val message = if (running) {
                "Looking for devices on this Wi-Fi..."
            } else {
                "No saved computers yet."
            }
            peersBox.addView(body(message).apply { setPadding(0, dp(4), 0, dp(4)) })
            return
        }

        for (peer in all) {
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(0, dp(10), 0, dp(10))
            }
            val text = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
            text.addView(
                TextView(this).apply {
                    this.text = peer.alias
                    textSize = 16f
                    setTextColor(INK)
                    typeface = Typeface.DEFAULT_BOLD
                },
            )
            text.addView(
                TextView(this).apply {
                    this.text = "${peer.address}:${peer.port}"
                    textSize = 12f
                    setTextColor(INK2)
                },
            )
            row.addView(text, LinearLayout.LayoutParams(0, WRAP, 1f))
            row.addView(
                primary("Send") { sendTo(peer) }.apply { textSize = 14f },
                LinearLayout.LayoutParams(dp(88), dp(44)),
            )
            if (manual.any { it.fingerprint == peer.fingerprint }) {
                row.setOnLongClickListener {
                    forget(peer)
                    true
                }
            }
            peersBox.addView(row)
            peersBox.addView(View(this).apply { setBackgroundColor(LINE) }, LinearLayout.LayoutParams(MATCH, 1))
        }
    }

    private fun addByIp() {
        val input = EditText(this).apply {
            hint = "192.168.1.20"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            setSingleLine(true)
            typeface = Typeface.DEFAULT
            setTextColor(INK)
            setHintTextColor(INK2)
        }
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(22), dp(10), dp(22), 0)
        }
        box.addView(input)

        AlertDialog.Builder(this)
            .setTitle("Add a computer")
            .setMessage("Enter the address shown by bhejo receive.")
            .setView(box)
            .setPositiveButton("Connect") { _, _ ->
                val host = input.text.toString().trim()
                if (host.isNotEmpty()) probeHost(host)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun probeHost(host: String) {
        log("looking for $host ...")
        thread(name = "bhejo-probe", isDaemon = true) {
            try {
                val info = Sender.probe(host, 53317, "")
                val fingerprint = info.optString("fingerprint", "")
                if (fingerprint.length != 64) throw java.io.IOException("that address is not a bhejo device")
                val alias = info.optString("alias", host).ifBlank { host }
                ui.post { confirmPeer(alias, host, 53317, fingerprint) }
            } catch (e: Exception) {
                ui.post { log("no answer from $host: ${e.message}") }
            }
        }
    }

    private fun confirmPeer(alias: String, host: String, port: Int, fingerprint: String) {
        AlertDialog.Builder(this)
            .setTitle("Trust $alias?")
            .setMessage(
                "${Identity.pretty(fingerprint)}\n\n" +
                    "Compare this with the fingerprint on the computer. It is pinned from now on.",
            )
            .setPositiveButton("Trust") { _, _ ->
                val peer = Discovery.Peer(alias, host, port, fingerprint, System.currentTimeMillis())
                manual.removeAll { it.fingerprint == fingerprint }
                manual.add(peer)
                saveManualPeers()
                renderPeers()
                log("added $alias at $host")
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun forget(peer: Discovery.Peer) {
        AlertDialog.Builder(this)
            .setTitle("Forget ${peer.alias}?")
            .setMessage("The pinned fingerprint is removed. You will confirm it again next time.")
            .setPositiveButton("Forget") { _, _ ->
                manual.removeAll { it.fingerprint == peer.fingerprint }
                saveManualPeers()
                renderPeers()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun loadManualPeers() {
        manual.clear()
        val prefs = getSharedPreferences(PEERS, MODE_PRIVATE)
        for (value in prefs.all.values) {
            val parts = (value as? String)?.split("|") ?: continue
            if (parts.size != 4 || parts[3].length != 64) continue
            manual.add(
                Discovery.Peer(
                    alias = parts[0],
                    address = parts[1],
                    port = parts[2].toIntOrNull() ?: 53317,
                    fingerprint = parts[3],
                    lastSeen = 0L,
                ),
            )
        }
    }

    private fun saveManualPeers() {
        val editor = getSharedPreferences(PEERS, MODE_PRIVATE).edit().clear()
        for (peer in manual) {
            val alias = peer.alias.replace('|', ' ')
            editor.putString(peer.fingerprint, "$alias|${peer.address}|${peer.port}|${peer.fingerprint}")
        }
        editor.apply()
    }

    private fun sendTo(peer: Discovery.Peer) {
        if (picked.isEmpty()) {
            toast("Choose files first.")
            return
        }
        val batch = ArrayList(picked)
        log("sending ${plural(batch.size)} to ${peer.alias} ...")
        thread(name = "bhejo-send", isDaemon = true) {
            try {
                var last = 0L
                Sender.send(
                    context = this,
                    peer = peer,
                    files = batch,
                    pin = currentPin,
                    identity = identity,
                    onLog = { line -> ui.post { log(line) } },
                    onProgress = { name, sent, total ->
                        val now = System.currentTimeMillis()
                        if (now - last > 700 || (total > 0 && sent == total)) {
                            last = now
                            val percent = if (total > 0) ((sent * 100) / total).toInt() else 100
                            ui.post { log("$name $percent%") }
                        }
                    },
                )
                ui.post { log("done. all files delivered.") }
            } catch (e: Exception) {
                ui.post { log("send failed: ${e.message}") }
            }
        }
    }

    // ---- file picking -----------------------------------------------------

    private fun pickFiles() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)
        }
        startActivityForResult(intent, PICK_FILES)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != PICK_FILES || resultCode != RESULT_OK || data == null) return

        val uris = ArrayList<Uri>()
        val clip = data.clipData
        if (clip != null) {
            for (i in 0 until clip.itemCount) {
                val uri = clip.getItemAt(i).uri
                if (uri != null) uris.add(uri)
            }
        } else {
            val single = data.data
            if (single != null) uris.add(single)
        }

        picked.clear()
        for (uri in uris) {
            val resolved = describe(uri)
            if (resolved != null) picked.add(resolved)
        }
        if (picked.isEmpty()) {
            pickedLabel.text = "No files chosen."
            return
        }
        pickedLabel.text =
            "${plural(picked.size)} selected, ${formatBytes(picked.sumOf { it.size })}. Tap a device below to send."
        log("${plural(picked.size)} selected")
    }

    private fun describe(uri: Uri): PickedFile? {
        var name = "file"
        var size = -1L
        try {
            contentResolver.query(
                uri,
                arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE),
                null,
                null,
                null,
            )?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
                    if (nameIndex >= 0) name = cursor.getString(nameIndex) ?: name
                    if (sizeIndex >= 0 && !cursor.isNull(sizeIndex)) size = cursor.getLong(sizeIndex)
                }
            }
        } catch (_: Exception) {
        }

        if (size >= 0) return PickedFile(uri, name, size)

        return try {
            val copy = File(cacheDir, "outgoing-${System.currentTimeMillis()}")
            val input = contentResolver.openInputStream(uri) ?: return null
            input.use { source ->
                FileOutputStream(copy).use { target -> source.copyTo(target) }
            }
            PickedFile(Uri.fromFile(copy), name, copy.length())
        } catch (_: Exception) {
            null
        }
    }

    // ---- helpers ----------------------------------------------------------

    private fun log(line: String) {
        if (!::logView.isInitialized) return
        val time = java.text.SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        val existing = logView.text?.toString().orEmpty()
        val merged = if (existing.isEmpty()) "[$time] $line" else "$existing\n[$time] $line"
        val lines = merged.split('\n')
        logView.text = if (lines.size > 140) lines.takeLast(140).joinToString("\n") else merged
    }

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private fun rounded(color: Int, radius: Int): GradientDrawable = GradientDrawable().apply {
        setColor(color)
        cornerRadius = dp(radius).toFloat()
    }

    private fun roundedWithStroke(fill: Int, stroke: Int, radius: Int): GradientDrawable =
        GradientDrawable().apply {
            setColor(fill)
            setStroke(dp(1), stroke)
            cornerRadius = dp(radius).toFloat()
        }

    private fun plural(count: Int): String = if (count == 1) "1 file" else "$count files"

    private fun formatBytes(value: Long): String {
        if (value < 1024) return "$value B"
        val kb = value / 1024.0
        if (kb < 1024) return String.format(Locale.US, "%.1f KB", kb)
        val mb = kb / 1024.0
        if (mb < 1024) return String.format(Locale.US, "%.1f MB", mb)
        return String.format(Locale.US, "%.2f GB", mb / 1024.0)
    }

    companion object {
        private const val PICK_FILES = 41
        private const val PEERS = "bhejo-peers"

        private val MATCH = ViewGroup.LayoutParams.MATCH_PARENT
        private val WRAP = ViewGroup.LayoutParams.WRAP_CONTENT

        private val INK = 0xFF1D1D1F.toInt()
        private val INK2 = 0xFF6E6E73.toInt()
        private val LINE = 0xFFE8E8ED.toInt()
        private val SOFT = 0xFFF5F5F7.toInt()
        private val PAPER = 0xFFFFFFFF.toInt()
    }
}
