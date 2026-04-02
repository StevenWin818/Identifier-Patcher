package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.SecurityLevel
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.*
import java.util.concurrent.ConcurrentHashMap
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.interception.keystore.InterceptorUtils
import org.matrix.TEESimulator.logging.SystemLogger

/**
 * Intercepts calls to an `IKeystoreSecurityLevel` service (e.g., TEE or StrongBox). This is where
 * the core logic for key generation and import handling for modern Android resides.
 */
class KeyMintSecurityLevelInterceptor(
    private val original: IKeystoreSecurityLevel,
    private val securityLevel: Int,
) : BinderInterceptor() {

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
        val overrides = ConfigurationManager.getAttestationIdOverrides()
        if (overrides.isEmpty()) return Triple(params, 0, 0)

        val existingTags = mutableSetOf<Int>()
        var rewritten = 0
        var inserted = 0

        for (param in params) {
            existingTags.add(param.tag)
            val replacement = overrides[param.tag] ?: continue
            param.value = KeyParameterValue.blob(replacement)
            rewritten += 1
        }

        for ((tag, replacement) in overrides) {
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
        SystemLogger.debug(
            "[TX_ID: $txId] Software createOperation path retired. Forwarding to hardware service (uid=$callingUid)."
        )
        return TransactionResult.Continue
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

        // Stores interceptors for active cryptographic operations.
        private val interceptedOperations = ConcurrentHashMap<IBinder, OperationInterceptor>()

        fun removeOperationInterceptor(operationBinder: IBinder, backdoor: IBinder) {
            // Unregister from the native hook layer first.
            unregister(backdoor, operationBinder)

            if (interceptedOperations.remove(operationBinder) != null) {
                SystemLogger.debug("Removed operation interceptor for binder: $operationBinder")
            }
        }
    }
}
