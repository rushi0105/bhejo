package dev.bhejo.app

import android.content.Context
import android.net.Uri
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.URLEncoder
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

data class PickedFile(val uri: Uri, val name: String, val size: Long)

/**
 * The sending half. TLS is verified by certificate fingerprint learned from
 * discovery, not by a CA chain: the certificate is self-signed on purpose and
 * the pinned hash is the trust anchor. Everything is streamed, so a 2 GB file
 * uses the same memory as a 2 KB one.
 */
object Sender {

    private class Conn(val socket: SSLSocket) {
        val input: InputStream = BufferedInputStream(socket.inputStream)
        val output: OutputStream = socket.outputStream

        fun write(
            method: String,
            path: String,
            host: String,
            port: Int,
            headers: Map<String, String>,
            length: Long,
        ) {
            val head = buildString {
                append(method).append(' ').append(path).append(" HTTP/1.1\r\n")
                append("Host: ").append(host).append(':').append(port).append("\r\n")
                for ((key, value) in headers) append(key).append(": ").append(value).append("\r\n")
                append("Content-Length: ").append(length).append("\r\n")
                append("Connection: close\r\n\r\n")
            }
            output.write(head.toByteArray(Charsets.US_ASCII))
            output.flush()
        }

        fun readResponse(): Pair<Int, String> {
            val head = TlsHttpServer.readHead(input) ?: throw IOException("no response from peer")
            val lines = head.split("\r\n")
            if (lines.isEmpty()) throw IOException("empty response from peer")
            val status = lines[0].split(" ").getOrNull(1)?.toIntOrNull()
                ?: throw IOException("malformed status line")

            var length = 0L
            for (i in 1 until lines.size) {
                val colon = lines[i].indexOf(':')
                if (colon <= 0) continue
                val name = lines[i].substring(0, colon).trim()
                if (name.equals("Content-Length", ignoreCase = true)) {
                    length = lines[i].substring(colon + 1).trim().toLongOrNull() ?: 0L
                }
            }
            val body = if (length > 0) TlsHttpServer.readExact(input, length) else ByteArray(0)
            return status to String(body, Charsets.UTF_8)
        }

        fun close() {
            try {
                socket.close()
            } catch (_: Exception) {
            }
        }
    }

    fun probe(host: String, port: Int, expected: String): JSONObject {
        val conn = connect(host, port, expected)
        try {
            conn.write("GET", "/api/v1/info", host, port, mapOf("Accept" to "application/json"), 0)
            val (status, body) = conn.readResponse()
            if (status != 200) throw IOException("peer answered HTTP $status")
            return JSONObject(body)
        } finally {
            conn.close()
        }
    }

    fun send(
        context: Context,
        peer: Discovery.Peer,
        files: List<PickedFile>,
        pin: String?,
        identity: Identity,
        onLog: (String) -> Unit,
        onProgress: (String, Long, Long) -> Unit,
    ) {
        if (files.isEmpty()) throw IOException("no files selected")

        val info = probe(peer.address, peer.port, peer.fingerprint)
        val name = info.optString("alias", peer.alias)
        onLog("connected to $name at ${peer.address}:${peer.port}")

        val ids = files.indices.map { "f$it" }
        val prepare = JSONObject().apply {
            put(
                "info",
                JSONObject()
                    .put("alias", identity.alias)
                    .put("fingerprint", identity.fingerprint),
            )
            if (!pin.isNullOrBlank()) put("pin", pin)
            put(
                "files",
                JSONArray().apply {
                    files.forEachIndexed { index, file ->
                        put(
                            JSONObject()
                                .put("id", ids[index])
                                .put("fileName", file.name)
                                .put("size", file.size),
                        )
                    }
                },
            )
        }

        val body = prepare.toString().toByteArray(Charsets.UTF_8)
        val prep = connect(peer.address, peer.port, peer.fingerprint)
        val prepared: JSONObject
        try {
            prep.write(
                "POST",
                "/api/v1/prepare-upload",
                peer.address,
                peer.port,
                mapOf("Content-Type" to "application/json"),
                body.size.toLong(),
            )
            prep.output.write(body)
            prep.output.flush()
            val (status, text) = prep.readResponse()
            if (status != 200) throw IOException(describe(status, text))
            prepared = JSONObject(text)
        } finally {
            prep.close()
        }

        val sessionId = prepared.getString("sessionId")
        val grants = prepared.getJSONArray("files")
        val tokens = HashMap<String, String>()
        for (i in 0 until grants.length()) {
            val grant = grants.getJSONObject(i)
            tokens[grant.getString("id")] = grant.getString("token")
        }

        for ((index, file) in files.withIndex()) {
            val token = tokens[ids[index]]
                ?: throw IOException("peer did not grant access to ${file.name}")

            val conn = connect(peer.address, peer.port, peer.fingerprint)
            try {
                val path = "/api/v1/upload" +
                    "?sessionId=${encode(sessionId)}" +
                    "&fileId=${encode(ids[index])}" +
                    "&token=${encode(token)}"
                conn.write(
                    "POST",
                    path,
                    peer.address,
                    peer.port,
                    mapOf("Content-Type" to "application/octet-stream"),
                    file.size,
                )

                val digest = MessageDigest.getInstance("SHA-256")
                var sent = 0L
                val stream = if (file.uri.scheme == "file") {
                    FileInputStream(File(file.uri.path ?: throw IOException("bad file uri")))
                } else {
                    context.contentResolver.openInputStream(file.uri)
                } ?: throw IOException("cannot read ${file.name}")
                stream.use {
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        val read = it.read(buffer)
                        if (read < 0) break
                        conn.output.write(buffer, 0, read)
                        digest.update(buffer, 0, read)
                        sent += read
                        onProgress(file.name, sent, file.size)
                    }
                }
                conn.output.flush()

                if (sent != file.size) {
                    throw IOException("${file.name} changed while sending")
                }

                val (status, text) = conn.readResponse()
                if (status != 200) throw IOException(describe(status, text))

                val result = JSONObject(text)
                val remote = result.optString("sha256", "")
                if (remote.isNotEmpty() && remote != hex(digest.digest())) {
                    throw IOException("checksum mismatch for ${file.name}")
                }
                onLog("delivered ${file.name}")
            } finally {
                conn.close()
            }
        }
    }

    private fun connect(host: String, port: Int, expected: String): Conn {
        val context = SSLContext.getInstance("TLS")
        context.init(null, arrayOf(TrustAnyCertificate), SecureRandom())
        val socket = context.socketFactory.createSocket() as SSLSocket
        socket.connect(InetSocketAddress(host, port), 10_000)
        socket.soTimeout = 60_000
        socket.startHandshake()

        val certificate = socket.session.peerCertificates.firstOrNull() as? X509Certificate
            ?: throw IOException("peer presented no certificate")
        val actual = Identity.fingerprintOf(certificate)
        if (expected.isNotEmpty() && actual != expected) {
            socket.close()
            throw IOException(
                "certificate changed: expected ${expected.take(12)}..., got ${actual.take(12)}...",
            )
        }
        return Conn(socket)
    }

    private fun describe(status: Int, body: String): String {
        val detail = try {
            JSONObject(body).optString("error", "")
        } catch (_: Exception) {
            ""
        }
        return if (detail.isEmpty()) "peer answered HTTP $status" else detail
    }

    private fun encode(value: String): String = URLEncoder.encode(value, "UTF-8")

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

    /** Self-signed certificates are expected; the fingerprint above is the check. */
    private object TrustAnyCertificate : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }
}
