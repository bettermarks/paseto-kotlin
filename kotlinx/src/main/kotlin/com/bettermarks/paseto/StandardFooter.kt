package com.bettermarks.paseto

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable data class StandardFooter(@SerialName("kid") val keyId: String? = null)
