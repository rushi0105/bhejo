package dev.bhejo.app

import android.content.Context
import android.os.Build
import android.util.Base64
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Date
import java.util.UUID

/**
 * A persistent device identity: one RSA key and one self-signed certificate,
 * created once and reused. The fingerprint of that certificate is what the
 * other machine pins, so it must not change between launches.
 */
class Identity private constructor(
    val alias: String,
    val keyPair: KeyPair,
    val certificate: X509Certificate,
) {
    val fingerprint: String = fingerprintOf(certificate)

    companion object {
        private const val PREFS = "bhejo-identity"

        fun load(context: Context): Identity {
            val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val alias = prefs.getString("alias", null) ?: defaultAlias().also {
                prefs.edit().putString("alias", it).apply()
            }

            val keyText = prefs.getString("key", null)
            val certText = prefs.getString("cert", null)
            if (keyText != null && certText != null) {
                try {
                    val keyBytes = Base64.decode(keyText, Base64.NO_WRAP)
                    val key = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(keyBytes))
                    val certBytes = Base64.decode(certText, Base64.NO_WRAP)
                    val cert = CertificateFactory.getInstance("X.509")
                        .generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate
                    return Identity(alias, KeyPair(cert.publicKey, key), cert)
                } catch (_: Exception) {
                    // Corrupt state: fall through and create a new identity.
                }
            }

            val pair = KeyPairGenerator.getInstance("RSA")
                .apply { initialize(2048, SecureRandom()) }
                .generateKeyPair()
            val cert = selfSign(pair)
            prefs.edit()
                .putString("key", Base64.encodeToString(pair.private.encoded, Base64.NO_WRAP))
                .putString("cert", Base64.encodeToString(cert.encoded, Base64.NO_WRAP))
                .apply()
            return Identity(alias, pair, cert)
        }

        private fun defaultAlias(): String {
            val model = Build.MODEL?.trim().orEmpty()
            if (model.isEmpty()) return "Android phone"
            return model.take(48)
        }

        private fun selfSign(pair: KeyPair): X509Certificate {
            val now = System.currentTimeMillis()
            val name = X500Name("CN=bhejo-${UUID.randomUUID()}")
            val builder = JcaX509v3CertificateBuilder(
                name,
                BigInteger(96, SecureRandom()).abs(),
                Date(now - 86_400_000L),
                Date(now + 10L * 365L * 24L * 3600L * 1000L),
                name,
                pair.public,
            )
            val signer = JcaContentSignerBuilder("SHA256withRSA").build(pair.private)
            return JcaX509CertificateConverter().getCertificate(builder.build(signer))
        }

        /** Lowercase hex, no separators: the format the Node side stores and compares. */
        fun fingerprintOf(cert: X509Certificate): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(cert.encoded)
            val hex = "0123456789abcdef"
            val sb = StringBuilder(digest.size * 2)
            for (b in digest) {
                val v = b.toInt() and 0xff
                sb.append(hex[v ushr 4])
                sb.append(hex[v and 0x0f])
            }
            return sb.toString()
        }

        /** ab:cd:ef:... for humans. */
        fun pretty(fingerprint: String): String = fingerprint.chunked(2).joinToString(":")
    }
}
