package dev.bhejo.app

import android.content.ContentValues
import android.content.Context
import android.os.Environment
import android.provider.MediaStore
import android.webkit.MimeTypeMap
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

data class DeclaredFile(val id: String, val fileName: String, val size: Long)

/** One transfer offer waiting for the person holding the phone to decide. */
class IncomingTransfer(
    val id: String,
    val alias: String,
    val files: List<DeclaredFile>,
    val totalBytes: Long,
) {
    internal val decision = CompletableFuture<Boolean>()

    fun accept() {
        decision.complete(true)
    }

    fun decline() {
        decision.complete(false)
    }
}

/**
 * Implements the receiving half of the Bhejo protocol:
 *
 *   GET  /api/v1/info
 *   POST /api/v1/prepare-upload
 *   POST /api/v1/upload?sessionId=&fileId=&token=
 *   POST /api/v1/cancel?sessionId=
 *
 * Files land in Downloads/Bhejo through MediaStore, so no storage permission
 * is needed and the files show up in the Downloads app immediately.
 */
class Receiver(
    private val context: Context,
    private val identity: Identity,
    private val onIncoming: (IncomingTransfer) -> Unit,
    private val onLog: (String) -> Unit,
) {
    private class SessionFile(val fileName: String, val size: Long, val token: String)
    private class Session(val files: MutableMap<String, SessionFile>, val expiresAt: Long)

    private val sessions = ConcurrentHashMap<String, Session>()
    private val random = SecureRandom()

    val server = TlsHttpServer(identity) { request -> handle(request) }

    @Volatile
    var pin: String? = null

    fun start() {
        server.start(53317)
    }

    fun stop() {
        server.stop()
        sessions.clear()
    }

    private fun handle(request: HttpRequest): HttpReply {
        return when {
            request.method == "GET" && request.path == "/api/v1/info" ->
                HttpReply(200, json = infoJson())

            request.method == "POST" && request.path == "/api/v1/prepare-upload" ->
                prepare(request)

            request.method == "POST" && request.path == "/api/v1/upload" ->
                upload(request)

            request.method == "POST" && request.path == "/api/v1/cancel" ->
                cancel(request)

            request.method == "GET" && request.path == "/" ->
                HttpReply(200, text = "bhejo is receiving.\n")

            else -> HttpReply(404, json = error("unknown route ${request.method} ${request.path}"))
        }
    }

    private fun infoJson(): String {
        val json = JSONObject()
        json.put("app", "bhejo")
        json.put("proto", 1)
        json.put("alias", identity.alias)
        json.put("deviceType", "mobile")
        json.put("fingerprint", identity.fingerprint)
        json.put("requiresPin", pin != null)
        return json.toString()
    }

    private fun prepare(request: HttpRequest): HttpReply {
        if (request.contentLength <= 0 || request.contentLength > 1_000_000) {
            return HttpReply(400, json = error("expected a small JSON body"))
        }

        val body = TlsHttpServer.readExact(request.body, request.contentLength)
        val payload = try {
            JSONObject(String(body, Charsets.UTF_8))
        } catch (_: Exception) {
            return HttpReply(400, json = error("invalid JSON"))
        }

        val requiredPin = pin
        if (requiredPin != null && payload.optString("pin", "") != requiredPin) {
            onLog("refused a transfer: wrong PIN")
            return HttpReply(403, json = error("wrong or missing PIN"))
        }

        val array = payload.optJSONArray("files")
            ?: return HttpReply(400, json = error("files is required"))
        if (array.length() == 0) return HttpReply(400, json = error("nothing to send"))
        if (array.length() > 500) return HttpReply(413, json = error("too many files"))

        val declared = ArrayList<DeclaredFile>(array.length())
        for (i in 0 until array.length()) {
            val item = array.optJSONObject(i)
                ?: return HttpReply(400, json = error("malformed file entry"))
            val id = item.optString("id", "")
            val name = item.optString("fileName", "")
            val size = item.optLong("size", -1)
            if (id.isEmpty() || name.isEmpty() || size < 0) {
                return HttpReply(400, json = error("each file needs id, fileName and size"))
            }
            declared.add(DeclaredFile(id, name, size))
        }

        val info = payload.optJSONObject("info")
        val alias = info?.optString("alias")?.trim()?.takeIf { it.isNotEmpty() }?.take(64)
            ?: "unknown device"

        val transfer = IncomingTransfer(randomHex(8), alias, declared, declared.sumOf { it.size })
        onIncoming(transfer)

        val accepted = try {
            transfer.decision.get(120, TimeUnit.SECONDS)
        } catch (_: Exception) {
            false
        }
        if (!accepted) {
            onLog("declined a transfer from $alias")
            return HttpReply(403, json = error("declined by the receiving device"))
        }

        val sessionId = randomHex(12)
        val session = Session(HashMap(), System.currentTimeMillis() + 10 * 60_000)
        val grants = JSONArray()
        for (file in declared) {
            val token = randomHex(16)
            session.files[file.id] = SessionFile(file.fileName, file.size, token)
            grants.put(JSONObject().put("id", file.id).put("token", token))
        }
        sessions[sessionId] = session
        onLog("accepted ${declared.size} file(s) from $alias")
        return HttpReply(
            200,
            json = JSONObject().put("sessionId", sessionId).put("files", grants).toString(),
        )
    }

    private fun upload(request: HttpRequest): HttpReply {
        val sessionId = request.query["sessionId"]
        val fileId = request.query["fileId"]
        val token = request.query["token"]
        if (sessionId == null || fileId == null || token == null) {
            return HttpReply(400, json = error("sessionId, fileId and token are required"))
        }

        val session = sessions[sessionId] ?: return HttpReply(403, json = error("unknown session"))
        if (session.expiresAt < System.currentTimeMillis()) {
            sessions.remove(sessionId)
            return HttpReply(403, json = error("session expired"))
        }

        val file = session.files[fileId] ?: return HttpReply(403, json = error("unknown file id"))
        if (file.token != token) return HttpReply(403, json = error("bad file token"))
        if (request.contentLength < 0) return HttpReply(400, json = error("content-length required"))
        if (file.size > 0 && request.contentLength != file.size) {
            return HttpReply(400, json = error("size mismatch: declared ${file.size}, got ${request.contentLength}"))
        }

        val name = safeName(file.fileName)
        val resolver = context.contentResolver
        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, name)
            put(MediaStore.MediaColumns.MIME_TYPE, mimeOf(name))
            put(
                MediaStore.MediaColumns.RELATIVE_PATH,
                Environment.DIRECTORY_DOWNLOADS + "/Bhejo",
            )
            put(MediaStore.MediaColumns.IS_PENDING, 1)
        }

        val uri = try {
            resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
        } catch (e: Exception) {
            null
        } ?: return HttpReply(500, json = error("could not create the file in Downloads"))

        val digest = MessageDigest.getInstance("SHA-256")
        var received = 0L
        try {
            val out = resolver.openOutputStream(uri) ?: throw IOException("no output stream")
            out.use { stream ->
                val buffer = ByteArray(64 * 1024)
                var remaining = request.contentLength
                while (remaining > 0) {
                    val want = minOf(buffer.size.toLong(), remaining).toInt()
                    val read = request.body.read(buffer, 0, want)
                    if (read < 0) throw IOException("connection closed early")
                    stream.write(buffer, 0, read)
                    digest.update(buffer, 0, read)
                    received += read
                    remaining -= read
                }
                stream.flush()
            }
        } catch (e: Exception) {
            try {
                resolver.delete(uri, null, null)
            } catch (_: Exception) {
            }
            onLog("write failed: ${e.message}")
            return HttpReply(500, json = error("write failed: ${e.message}"))
        }

        val publish = ContentValues().apply { put(MediaStore.MediaColumns.IS_PENDING, 0) }
        resolver.update(uri, publish, null, null)

        onLog("saved $name (${formatBytes(received)})")
        return HttpReply(
            200,
            json = JSONObject()
                .put("ok", true)
                .put("fileName", name)
                .put("sha256", hex(digest.digest()))
                .toString(),
        )
    }

    private fun cancel(request: HttpRequest): HttpReply {
        val sessionId = request.query["sessionId"]
        if (sessionId != null) sessions.remove(sessionId)
        return HttpReply(200, json = """{"ok":true}""")
    }

    private fun safeName(raw: String): String {
        val base = raw.substringAfterLast('/').substringAfterLast('\\')
        val cleaned = buildString {
            for (c in base) {
                append(if (c.code < 0x20 || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|') '_' else c)
            }
        }.trim().trim('.')
        if (cleaned.isEmpty() || cleaned == "." || cleaned == "..") return "bhejo-file"
        return if (cleaned.length > 120) {
            val dot = cleaned.lastIndexOf('.')
            if (dot > 0 && cleaned.length - dot <= 10) {
                cleaned.take(110) + cleaned.substring(dot)
            } else {
                cleaned.take(120)
            }
        } else {
            cleaned
        }
    }

    private fun mimeOf(name: String): String {
        val ext = name.substringAfterLast('.', "").lowercase()
        return MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext) ?: "application/octet-stream"
    }

    private fun randomHex(bytes: Int): String {
        val buffer = ByteArray(bytes)
        random.nextBytes(buffer)
        return hex(buffer)
    }

    private fun hex(bytes: ByteArray): String {
        val alphabet = "0123456789abcdef"
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xff
            sb.append(alphabet[v ushr 4])
            sb.append(alphabet[v and 0x0f])
        }
        return sb.toString()
    }

    private fun formatBytes(value: Long): String {
        if (value < 1024) return "$value B"
        val kb = value / 1024.0
        if (kb < 1024) return String.format("%.1f KB", kb)
        val mb = kb / 1024.0
        if (mb < 1024) return String.format("%.1f MB", mb)
        return String.format("%.2f GB", mb / 1024.0)
    }

    private fun error(message: String): String =
        JSONObject().put("error", message).toString()
}
