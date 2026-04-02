package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.SecurityLevel
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.*
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.cert.Certificate
import java.util.concurrent.ConcurrentHashMap
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.interception.keystore.InterceptorUtils
import org.matrix.TEESimulator.interception.keystore.KeyIdentifier
import org.matrix.TEESimulator.logging.SystemLogger

/**
 * Intercepts calls to an `IKeystoreSecurityLevel` service (e.g., TEE or StrongBox). This is where
 * the core logic for key generation and import handling for modern Android resides.
 */
class KeyMintSecurityLevelInterceptor(
    private val original: IKeystoreSecurityLevel,
    private val securityLevel: Int,
) : BinderInterceptor() {

    // --- Data Structures for State Management ---
    data class GeneratedKeyInfo(
        val keyPair: KeyPair,
        val nspace: Long,
        val response: KeyEntryResponse,
    )

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
        val shouldSkip = ConfigurationManager.shouldSkipUid(callingUid)

        when (code) {
            GENERATE_KEY_TRANSACTION -> {
                logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)

                if (!shouldSkip) {
                    rewriteGenerateKeyAttestationIds(txId, callingUid, data)
                    return TransactionResult.OverrideData(data)
                } else {
                    val packages = ConfigurationManager.getPackagesForUid(callingUid).joinToString()
                    SystemLogger.debug(
                        "[TX_ID: $txId] Skip generateKey rewrite for uid=$callingUid packages=[$packages] (not matched by target rules)."
                    )
                }
            }
            CREATE_OPERATION_TRANSACTION -> {
                logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)

                if (!shouldSkip) return handleCreateOperation(txId, callingUid, data)
            }
            IMPORT_KEY_TRANSACTION -> {
                logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)

                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!
                SystemLogger.info(
                    "[TX_ID: $txId] Forward to post-importKey hook for ${keyDescriptor.alias}[${keyDescriptor.nspace}]"
                )
                return TransactionResult.Continue
            }
        }

        logTransaction(
            txId,
            transactionNames[code] ?: "unknown code=$code",
            callingUid,
            callingPid,
            true,
        )

        return TransactionResult.ContinueAndSkipPost
    }

    override fun onPostTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
        reply: Parcel?,
        resultCode: Int,
    ): TransactionResult {
        // We only care about successful transactions.
        if (resultCode != 0 || reply == null || InterceptorUtils.hasException(reply))
            return TransactionResult.SkipTransaction

        if (code == IMPORT_KEY_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)

            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor =
                data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.SkipTransaction
            cleanupKeyData(KeyIdentifier(callingUid, keyDescriptor.alias))
        } else if (code == CREATE_OPERATION_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)

            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!
            val params = data.createTypedArray(KeyParameter.CREATOR)!!
            val parsedParams = KeyMintAttestation(params)
            val forced = data.readBoolean()
            if (forced)
                SystemLogger.verbose(
                    "[TX_ID: $txId] Current operation has a very high pruning power."
                )
            val response: CreateOperationResponse =
                reply.readTypedObject(CreateOperationResponse.CREATOR)!!
            SystemLogger.verbose(
                "[TX_ID: $txId] CreateOperationResponse: ${response.iOperation} ${response.operationChallenge}"
            )

            // Intercept the IKeystoreOperation binder
            response.iOperation?.let { operation ->
                val operationBinder = operation.asBinder()
                if (!interceptedOperations.containsKey(operationBinder)) {
                    SystemLogger.info("Found new IKeystoreOperation. Registering interceptor...")
                    val backdoor = getBackdoor(target)
                    if (backdoor != null) {
                        val interceptor = OperationInterceptor(operation, backdoor)
                        register(backdoor, operationBinder, interceptor)
                        interceptedOperations[operationBinder] = interceptor
                    } else {
                        SystemLogger.error(
                            "Failed to get backdoor to register OperationInterceptor."
                        )
                    }
                }
            }
        }
        return TransactionResult.SkipTransaction
    }

    private fun rewriteGenerateKeyAttestationIds(txId: Long, callingUid: Int, data: Parcel) {
        runCatching {
                data.setDataPosition(0)
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)

                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                val attestationKey = data.readTypedObject(KeyDescriptor.CREATOR)
                val params = data.createTypedArray(KeyParameter.CREATOR)
                val flags = if (data.dataAvail() > 0) data.readInt() else 0
                val entropy = if (data.dataAvail() > 0) data.createByteArray() else null

                if (keyDescriptor == null || params == null) {
                    SystemLogger.warning(
                        "[TX_ID: $txId] Failed to parse generateKey parcel. Forwarding original payload."
                    )
                    data.setDataPosition(0)
                    return
                }

                val packageNames =
                    ConfigurationManager.getPackagesForUid(callingUid)
                        .joinToString()
                val (rewrittenParams, rewrittenCount, insertedCount) =
                    rewriteAttestationIdParams(params)

                data.setDataPosition(0)
                data.writeInterfaceToken(IKeystoreSecurityLevel.DESCRIPTOR)
                data.writeTypedObject(keyDescriptor, 0)
                data.writeTypedObject(attestationKey, 0)
                data.writeTypedArray(rewrittenParams, 0)
                data.writeInt(flags)
                data.writeByteArray(entropy)
                data.setDataSize(data.dataPosition())
                data.setDataPosition(0)

                SystemLogger.info(
                    "[TX_ID: $txId] generateKey rewrite result alias=${keyDescriptor.alias}, packages=[$packageNames], rewritten=$rewrittenCount, inserted=$insertedCount, totalParams=${rewrittenParams.size}."
                )
            }
            .onFailure {
                SystemLogger.error(
                    "[TX_ID: $txId] Failed to rewrite generateKey attestation IDs. Forwarding original payload.",
                    it,
                )
                data.setDataPosition(0)
            }
    }

    private fun rewriteAttestationIdParams(
        params: Array<KeyParameter>
    ): Triple<Array<KeyParameter>, Int, Int> {
        val rewrittenParams = params.toMutableList()
        val existingTags = mutableSetOf<Int>()
        var rewritten = 0
        var inserted = 0

        for (param in params) {
            existingTags.add(param.tag)
            val replacement = attestationIdOverrides[param.tag] ?: continue
            param.value = KeyParameterValue.blob(replacement)
            rewritten += 1
        }

        for ((tag, replacement) in attestationIdOverrides) {
            if (existingTags.contains(tag)) continue

            rewrittenParams +=
                KeyParameter().apply {
                    this.tag = tag
                    this.value = KeyParameterValue.blob(replacement)
                }
            inserted += 1
        }

        return Triple(rewrittenParams.toTypedArray(), rewritten, inserted)
    }

    /**
     * Handles the `createOperation` transaction. It checks if the operation is for a key that was
     * generated in software. If so, it creates a software-based operation handler. Otherwise, it
     * lets the call proceed to the real hardware service.
     */
    private fun handleCreateOperation(
        txId: Long,
        callingUid: Int,
        data: Parcel,
    ): TransactionResult {
        data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
        val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!

        // An operation must use the KEY_ID domain.
        if (keyDescriptor.domain != Domain.KEY_ID) {
            return TransactionResult.ContinueAndSkipPost
        }

        val nspace = keyDescriptor.nspace
        val generatedKeyInfo = findGeneratedKeyByKeyId(callingUid, nspace)

        if (generatedKeyInfo == null) {
            SystemLogger.debug(
                "[TX_ID: $txId] Operation for unknown/hardware KeyId ($nspace). Forwarding."
            )
            return TransactionResult.Continue
        }

        SystemLogger.info("[TX_ID: $txId] Creating SOFTWARE operation for KeyId $nspace.")

        val params = data.createTypedArray(KeyParameter.CREATOR)!!
        val parsedParams = KeyMintAttestation(params)

        val softwareOperation = SoftwareOperation(txId, generatedKeyInfo.keyPair, parsedParams)
        val operationBinder = SoftwareOperationBinder(softwareOperation)

        val response =
            CreateOperationResponse().apply {
                iOperation = operationBinder
                operationChallenge = null
            }

        return InterceptorUtils.createTypedObjectReply(response)
    }

    companion object {
        // Transaction codes for IKeystoreSecurityLevel interface.
        private val GENERATE_KEY_TRANSACTION =
            InterceptorUtils.getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "generateKey")
        private val IMPORT_KEY_TRANSACTION =
            InterceptorUtils.getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "importKey")
        private val CREATE_OPERATION_TRANSACTION =
            InterceptorUtils.getTransactCode(
                IKeystoreSecurityLevel.Stub::class.java,
                "createOperation",
            )

        private val transactionNames: Map<Int, String> by lazy {
            IKeystoreSecurityLevel.Stub::class
                .java
                .declaredFields
                .filter {
                    it.isAccessible = true
                    it.type == Int::class.java && it.name.startsWith("TRANSACTION_")
                }
                .associate { field -> (field.get(null) as Int) to field.name.split("_")[1] }
        }

        private val attestationIdOverrides =
            mapOf(
                Tag.ATTESTATION_ID_DEVICE to "pudding".toByteArray(StandardCharsets.UTF_8),
                Tag.ATTESTATION_ID_PRODUCT to "pudding".toByteArray(StandardCharsets.UTF_8),
                Tag.ATTESTATION_ID_MODEL to "25113PN0EC".toByteArray(StandardCharsets.UTF_8),
                Tag.ATTESTATION_ID_BRAND to "Xiaomi".toByteArray(StandardCharsets.UTF_8),
                Tag.ATTESTATION_ID_MANUFACTURER to "Xiaomi".toByteArray(StandardCharsets.UTF_8),
            )

        // Stores keys generated entirely in software.
        val generatedKeys = ConcurrentHashMap<KeyIdentifier, GeneratedKeyInfo>()
        // A set to quickly identify keys that were generated for attestation purposes.
        val attestationKeys = ConcurrentHashMap.newKeySet<KeyIdentifier>()
        // Caches patched certificate chains to prevent re-generation and signature inconsistencies.
        val patchedChains = ConcurrentHashMap<KeyIdentifier, Array<Certificate>>()
        // Stores interceptors for active cryptographic operations.
        private val interceptedOperations = ConcurrentHashMap<IBinder, OperationInterceptor>()

        // --- Public Accessors for Other Interceptors ---
        fun getGeneratedKeyResponse(keyId: KeyIdentifier): KeyEntryResponse? =
            generatedKeys[keyId]?.response

        /**
         * Finds a software-generated key by first filtering all known keys by the caller's UID, and
         * then matching the specific nspace.
         *
         * @param callingUid The UID of the process that initiated the createOperation call.
         * @param nspace The unique key identifier from the operation's KeyDescriptor.
         * @return The matching GeneratedKeyInfo if found, otherwise null.
         */
        fun findGeneratedKeyByKeyId(callingUid: Int, nspace: Long?): GeneratedKeyInfo? {
            // Iterate through all entries in the map to check both the key (for UID) and value (for
            // nspace).
            if (nspace == null || nspace == 0L) return null
            return generatedKeys.entries
                .filter { (keyIdentifier, _) -> keyIdentifier.uid == callingUid }
                .find { (_, info) -> info.nspace == nspace }
                ?.value
        }

        fun getPatchedChain(keyId: KeyIdentifier): Array<Certificate>? = patchedChains[keyId]

        fun isAttestationKey(keyId: KeyIdentifier): Boolean = attestationKeys.contains(keyId)

        fun cleanupKeyData(keyId: KeyIdentifier) {
            if (generatedKeys.remove(keyId) != null) {
                SystemLogger.debug("Remove generated key ${keyId}")
            }
            if (patchedChains.remove(keyId) != null) {
                SystemLogger.debug("Remove patched chain for ${keyId}")
            }
            if (attestationKeys.remove(keyId)) {
                SystemLogger.debug("Remove cached attestaion key ${keyId}")
            }
        }

        fun removeOperationInterceptor(operationBinder: IBinder, backdoor: IBinder) {
            // Unregister from the native hook layer first.
            unregister(backdoor, operationBinder)

            if (interceptedOperations.remove(operationBinder) != null) {
                SystemLogger.debug("Removed operation interceptor for binder: $operationBinder")
            }
        }

        // Clears all cached keys.
        fun clearAllGeneratedKeys(reason: String? = null) {
            val count = generatedKeys.size
            val reasonMessage = reason?.let { " due to $it" } ?: ""
            generatedKeys.clear()
            patchedChains.clear()
            attestationKeys.clear()
            SystemLogger.info("Cleared all cached keys ($count entries)$reasonMessage.")
        }
    }
}
