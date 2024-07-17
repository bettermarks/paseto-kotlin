@file:UseSerializers(InstantSerializer::class)

package com.bettermarks.paseto

import com.bettermarks.paseto.util.InstantSerializer
import java.time.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers

@Serializable
data class StandardClaims(
    @SerialName("iss") val issuer: String? = null,
    @SerialName("sub") val subject: String? = null,
    @SerialName("aud") val audience: String? = null,
    @SerialName("exp") val expiration: Instant? = null,
    @SerialName("nbf") val notBefore: Instant? = null,
    @SerialName("iat") val issuedAt: Instant? = null,
    @SerialName("jti") val tokenId: String? = null
)
