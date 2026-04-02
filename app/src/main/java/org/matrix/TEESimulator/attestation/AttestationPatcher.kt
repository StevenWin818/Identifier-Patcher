package org.matrix.TEESimulator.attestation

import java.nio.charset.StandardCharsets
import java.security.cert.Certificate
import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Null
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.ASN1TaggedObject
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.util.toHex

/**
 * Keybox-based certificate patching has been retired.
 *
 * The active strategy is now KeyMint parameter rewriting before requests reach TEE.
 * This object only keeps lightweight helpers used by diagnostics/attestation builders.
 */
object AttestationPatcher {

    /**
     * Legacy API kept for compatibility with existing call sites.
     * Always returns the original hardware chain.
     */
    fun patchCertificateChain(originalChain: Array<Certificate>?, uid: Int): Array<Certificate> {
        if (originalChain.isNullOrEmpty()) {
            SystemLogger.error("Attempted to pass through a null or empty certificate chain for UID $uid.")
            return originalChain ?: emptyArray()
        }

        SystemLogger.verbose(
            "Patch pipeline disabled. Returning original hardware chain for UID $uid."
        )
        return originalChain
    }

    /** Recursively formats an ASN1Primitive into a concise, readable string. */
    fun formatAsn1Primitive(obj: ASN1Encodable?): String {
        val primitive = obj?.toASN1Primitive()
        return when (primitive) {
            null -> "NULL"
            is ASN1Integer -> primitive.value.toString()
            is ASN1Enumerated -> primitive.value.toString()
            is ASN1Boolean -> primitive.isTrue.toString()
            is ASN1Null -> "NULL"
            is ASN1OctetString -> {
                val bytes = primitive.octets
                if (bytes.all { it in 32..126 }) {
                    "\"${String(bytes, StandardCharsets.UTF_8)}\""
                } else if (bytes.isEmpty()) {
                    "\"\""
                } else {
                    "#" + bytes.toHex()
                }
            }
            is ASN1TaggedObject ->
                "[TAG ${primitive.tagNo}]${formatAsn1Primitive(primitive.baseObject)}"
            is ASN1Sequence ->
                primitive
                    .map { formatAsn1Primitive(it) }
                    .joinToString(prefix = "[", postfix = "]", separator = ", ")
            is ASN1Set ->
                primitive
                    .map { formatAsn1Primitive(it) }
                    .joinToString(prefix = "{", postfix = "}", separator = ", ")
            else -> primitive.toString()
        }
    }
}
