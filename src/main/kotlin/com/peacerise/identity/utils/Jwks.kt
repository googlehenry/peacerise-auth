package com.peacerise.identity.utils

import com.nimbusds.jose.jwk.RSAKey
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*

class Jwks {
    companion object {
        fun generateRsa(): RSAKey {
            val keyPair: KeyPair = generateRsaKey()
            val publicKey = keyPair.public as RSAPublicKey
            val privateKey = keyPair.private as RSAPrivateKey
            // @formatter:off
            return RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build()
            // @formatter:on
        }

        fun generateRsaKey(): KeyPair {
            return try {
                val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
                keyPairGenerator.initialize(2048)
                keyPairGenerator.generateKeyPair()
            } catch (ex: Exception) {
                throw IllegalStateException(ex)
            }
        }
    }
}