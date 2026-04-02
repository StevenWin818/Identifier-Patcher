package org.matrix.TEESimulator.interception.keystore

import android.annotation.SuppressLint
import android.os.IBinder
import android.os.Parcel
import android.security.keystore.IKeystoreService

/**
 * Interceptor for the legacy `IKeystoreService` on Android Q (API 29) and R (API 30).
 *
 * Legacy keybox/software-generation paths were retired. The active implementation is a passthrough
 * interceptor that only keeps observability and lifecycle compatibility.
 */
@SuppressLint("BlockedPrivateApi", "PrivateApi")
object KeystoreInterceptor : AbstractKeystoreInterceptor() {

    private val transactionNames: Map<Int, String> by lazy {
        IKeystoreService.Stub::class
            .java
            .declaredFields
            .filter {
                it.isAccessible = true
                it.type == Int::class.java && it.name.startsWith("TRANSACTION_")
            }
            .associate { field -> (field.get(null) as Int) to field.name.split("_")[1] }
    }

    override val serviceName = "android.security.keystore"
    override val processName = "keystore"
    override val injectionCommand = "exec ./inject `pidof keystore` libTEESimulator.so entry"

    override fun onPreTransact(
        txId: Long,
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): TransactionResult {
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
        return TransactionResult.SkipTransaction
    }
}
