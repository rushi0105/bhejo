package dev.bhejo.app

import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.URLDecoder
import java.security.KeyStore
import java.security.SecureRandom
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import kotlin.concurrent.thread

/**
 * A very small HTTPS server built directly on SSLServerSocket.
 *
 * Android has no com.sun.net.httpserver, and the protocol Bhejo speaks is only
 * four routes with a raw body, so hand-parsing the head is both smaller and
 * easier to audit than pulling in a server framework.
 */
data class HttpRequest(
    val method: String,
    val path: String,
    val query: Map<String, String>,
    val headers: Map<String, String>,
    val body: InputStream,
    val contentLength: Long,
    val remote: String,
)

class HttpReply(
    val status: Int,
    val json: String? = null,
    val text: String? = null,
)

class TlsHttpServer(
    private val identity: Identity,
    private val handler: (HttpRequest) -> HttpReply,
) {
    @Volatile
    var port: Int = 0
        private set

    private var server: SSLServerSocket? = null

    @Volatile
    private var running = false

    fun start(preferredPort: Int = 53317) {
        if (running) return
        val socket = context().serverSocketFactory.createServerSocket() as SSLServerSocket
        socket.reuseAddress = true
        try {
            socket.bind(InetSocketAddress(preferredPort))
        } catch (_: Exception) {
            socket.bind(InetSocketAddress(0))
        }
        server = socket
        port = socket.localPort
        running = true

        thread(name = "bhejo-tls", isDaemon = true) {
            while (running) {
                val accepted = try {
                    socket.accept() as SSLSocket
                } catch (_: Exception) {
                    if (!running) break
                    continue
                }
                thread(name = "bhejo-tls-conn", isDaemon = true) { serve(accepted) }
            }
        }
    }

    fun stop() {
        running = false
        try {
            server?.close()
        } catch (_: Exception) {
        }
        server = null
    }

    private fun context(): SSLContext {
        val store = KeyStore.getInstance("PKCS12")
        store.load(null, null)
        store.setKeyEntry("bhejo", identity.keyPair.private, PASSWORD, arrayOf(identity.certificate))

        val factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        factory.init(store, PASSWORD)

        val context = SSLContext.getInstance("TLS")
        context.init(factory.keyManagers, null, SecureRandom())
        return context
    }

    private fun serve(socket: SSLSocket) {
        try {
            socket.soTimeout = 30_000
            socket.startHandshake()

            val input = BufferedInputStream(socket.inputStream)
            val head = readHead(input) ?: return
            val lines = head.split("\r\n")
            if (lines.isEmpty()) return

            val first = lines[0].split(" ")
            if (first.size < 2) return
            val method = first[0].uppercase()
            val target = first[1]
            val mark = target.indexOf('?')
            val path = if (mark >= 0) target.substring(0, mark) else target
            val query = if (mark >= 0) parseQuery(target.substring(mark + 1)) else emptyMap()

            val headers = HashMap<String, String>()
            for (i in 1 until lines.size) {
                val colon = lines[i].indexOf(':')
                if (colon > 0) {
                    headers[lines[i].substring(0, colon).trim().lowercase()] =
                        lines[i].substring(colon + 1).trim()
                }
            }

            val length = headers["content-length"]?.toLongOrNull() ?: 0L
            val remote = socket.inetAddress?.hostAddress ?: "unknown"

            val reply = try {
                handler(HttpRequest(method, path, query, headers, input, length, remote))
            } catch (e: Exception) {
                HttpReply(500, json = """{"error":${quote(e.message ?: "internal error")}}""")
            }
            write(socket, reply)
        } catch (_: Exception) {
            // A dropped connection needs no reply.
        } finally {
            try {
                socket.close()
            } catch (_: Exception) {
            }
        }
    }

    private fun write(socket: SSLSocket, reply: HttpReply) {
        val body = (reply.json ?: reply.text ?: "").toByteArray(Charsets.UTF_8)
        val type = if (reply.json != null) "application/json" else "text/plain; charset=utf-8"
        val reason = when (reply.status) {
            200 -> "OK"
            400 -> "Bad Request"
            403 -> "Forbidden"
            404 -> "Not Found"
            405 -> "Method Not Allowed"
            413 -> "Payload Too Large"
            else -> "Internal Server Error"
        }
        val head = buildString {
            append("HTTP/1.1 ").append(reply.status).append(' ').append(reason).append("\r\n")
            append("Content-Type: ").append(type).append("\r\n")
            append("Content-Length: ").append(body.size).append("\r\n")
            append("Connection: close\r\n\r\n")
        }
        val out = socket.outputStream
        out.write(head.toByteArray(Charsets.US_ASCII))
        out.write(body)
        out.flush()
    }

    companion object {
        private val PASSWORD = charArrayOf('b', 'h', 'e', 'j', 'o')

        /** Read up to and including the blank line that ends the request head. */
        fun readHead(input: InputStream, limit: Int = 16_384): String? {
            val out = ByteArrayOutputStream(512)
            var state = 0
            while (true) {
                val byte = input.read()
                if (byte < 0) return null
                out.write(byte)
                state = when (state) {
                    0 -> if (byte == 13) 1 else 0
                    1 -> if (byte == 10) 2 else 0
                    2 -> if (byte == 13) 3 else 0
                    else -> if (byte == 10) 4 else 0
                }
                if (state == 4) break
                if (out.size() > limit) return null
            }
            return out.toString("ISO-8859-1")
        }

        fun parseQuery(query: String): Map<String, String> {
            val map = HashMap<String, String>()
            if (query.isEmpty()) return map
            for (pair in query.split('&')) {
                if (pair.isEmpty()) continue
                val mark = pair.indexOf('=')
                val key = if (mark < 0) pair else pair.substring(0, mark)
                val value = if (mark < 0) "" else pair.substring(mark + 1)
                map[URLDecoder.decode(key, "UTF-8")] = URLDecoder.decode(value, "UTF-8")
            }
            return map
        }

        fun readExact(input: InputStream, length: Long): ByteArray {
            require(length >= 0) { "negative length" }
            require(length <= Int.MAX_VALUE) { "body too large" }
            val out = ByteArrayOutputStream(length.toInt())
            val buffer = ByteArray(64 * 1024)
            var remaining = length
            while (remaining > 0) {
                val want = minOf(buffer.size.toLong(), remaining).toInt()
                val read = input.read(buffer, 0, want)
                if (read < 0) throw java.io.IOException("body ended early")
                out.write(buffer, 0, read)
                remaining -= read
            }
            return out.toByteArray()
        }

        fun quote(value: String): String {
            val sb = StringBuilder("\"")
            for (c in value) {
                when (c) {
                    '"' -> sb.append("\\\"")
                    '\\' -> sb.append("\\\\")
                    '\n' -> sb.append("\\n")
                    '\r' -> sb.append("\\r")
                    '\t' -> sb.append("\\t")
                    else -> if (c.code < 0x20) sb.append(String.format("\\u%04x", c.code)) else sb.append(c)
                }
            }
            sb.append('"')
            return sb.toString()
        }
    }
}
