package dev.bhejo.app

import android.content.Context
import android.net.wifi.WifiManager
import android.util.Log
import org.json.JSONObject
import java.net.DatagramPacket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.MulticastSocket
import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.thread

/**
 * The same beacon the desktop build uses: a JSON announcement every four
 * seconds on 224.0.0.167:53317 and on the broadcast address, answered with a
 * unicast reply so networks that filter multicast still work.
 */
class Discovery(
    private val identity: Identity,
    private val serverPort: () -> Int,
    private val onPeers: (List<Peer>) -> Unit,
    private val onLog: (String) -> Unit,
) {
    data class Peer(
        val alias: String,
        val address: String,
        val port: Int,
        val fingerprint: String,
        val lastSeen: Long,
    )

    private val group = InetAddress.getByName("224.0.0.167")
    private val port = 53317

    private val peers = ConcurrentHashMap<String, Peer>()

    @Volatile
    private var running = false

    @Volatile
    private var socket: MulticastSocket? = null
    private var lock: WifiManager.MulticastLock? = null

    fun start(context: Context) {
        if (running) return
        running = true

        try {
            val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            lock = wifi.createMulticastLock("bhejo").apply {
                setReferenceCounted(false)
                acquire()
            }
        } catch (e: Exception) {
            onLog("multicast lock unavailable: ${e.message}")
        }

        try {
            val s = MulticastSocket(null)
            s.reuseAddress = true
            s.bind(InetSocketAddress(port))
            s.timeToLive = 1
            s.broadcast = true
            try {
                s.joinGroup(group)
            } catch (e: Exception) {
                // Some interfaces (and most emulators) refuse IP_ADD_MEMBERSHIP.
                // The socket still receives broadcast announcements on this port,
                // and the unicast reply below keeps discovery alive.
                onLog("multicast unavailable, using broadcast: ${e.message}")
            }
            socket = s
            thread(name = "bhejo-rx", isDaemon = true) { receiveLoop(s) }
            thread(name = "bhejo-tx", isDaemon = true) { announceLoop(s) }
            thread(name = "bhejo-sweep", isDaemon = true) { sweepLoop() }
            onLog("discovery on udp $port")
        } catch (e: Exception) {
            running = false
            onLog("discovery failed: ${e.message}")
        }
    }

    fun stop() {
        running = false
        try {
            socket?.close()
        } catch (_: Exception) {
        }
        socket = null
        try {
            lock?.release()
        } catch (_: Exception) {
        }
        lock = null
        peers.clear()
        onPeers(emptyList())
    }

    private fun payload(): ByteArray {
        val json = JSONObject()
        json.put("app", "bhejo")
        json.put("proto", 1)
        json.put("alias", identity.alias)
        json.put("deviceType", "mobile")
        json.put("port", serverPort())
        json.put("fingerprint", identity.fingerprint)
        json.put("ts", System.currentTimeMillis())
        return json.toString().toByteArray(Charsets.UTF_8)
    }

    private fun announceLoop(s: MulticastSocket) {
        while (running) {
            try {
                val bytes = payload()
                try {
                    s.send(DatagramPacket(bytes, bytes.size, group, port))
                } catch (_: Exception) {
                }
                try {
                    val broadcast = InetAddress.getByName("255.255.255.255")
                    s.send(DatagramPacket(bytes, bytes.size, broadcast, port))
                } catch (_: Exception) {
                }
            } catch (e: Exception) {
                if (running) onLog("announce failed: ${e.message}")
            }
            try {
                Thread.sleep(4000)
            } catch (_: InterruptedException) {
                return
            }
        }
    }

    private fun receiveLoop(s: MulticastSocket) {
        val buffer = ByteArray(4096)
        while (running) {
            try {
                val packet = DatagramPacket(buffer, buffer.size)
                s.receive(packet)
                handle(packet)
            } catch (e: Exception) {
                if (!running) break
                Log.w("bhejo", "discovery receive: ${e.message}")
            }
        }
    }

    private fun handle(packet: DatagramPacket) {
        if (packet.length <= 0 || packet.length > 4096) return
        val msg = try {
            JSONObject(String(packet.data, 0, packet.length, Charsets.UTF_8))
        } catch (_: Exception) {
            return
        }

        if (msg.optString("app") != "bhejo") return
        if (msg.optInt("proto", 0) != 1) return

        val fingerprint = msg.optString("fingerprint", "")
        if (fingerprint.length != 64) return
        if (fingerprint == identity.fingerprint) return

        val httpPort = msg.optInt("port", 0)
        if (httpPort !in 1..65535) return

        val alias = msg.optString("alias", "").trim()
        if (alias.isEmpty()) return

        val host = packet.address?.hostAddress ?: return
        val known = peers.containsKey(fingerprint)
        peers[fingerprint] = Peer(
            alias = alias.take(64),
            address = host,
            port = httpPort,
            fingerprint = fingerprint,
            lastSeen = System.currentTimeMillis(),
        )
        publish()

        if (!known && packet.port > 0) {
            try {
                val bytes = payload()
                socket?.send(DatagramPacket(bytes, bytes.size, packet.address, packet.port))
            } catch (_: Exception) {
            }
        }
    }

    private fun sweepLoop() {
        while (running) {
            try {
                Thread.sleep(2000)
            } catch (_: InterruptedException) {
                return
            }
            val cutoff = System.currentTimeMillis() - 15_000
            var changed = false
            for ((key, peer) in peers) {
                if (peer.lastSeen < cutoff) {
                    peers.remove(key)
                    changed = true
                }
            }
            if (changed) publish()
        }
    }

    private fun publish() {
        onPeers(peers.values.sortedBy { it.alias.lowercase() })
    }
}
