package com.peacerise.auth.config

import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import org.springframework.core.io.ClassPathResource
import java.security.KeyStore
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*

class KeyStoreConfig {
    companion object{

        const val live_key_pair_id = "henry_key_pair_2003_03_22"
        fun loadKeyPairFromKeyStore(): List<RSAKey> {
            val ks = KeyStore.getInstance("pkcs12");
            val pwd = "123test321".toCharArray()

            val keyStoreFile = "/rsa-keys/henry_key_store.pkcs12.jks"
            ClassPathResource(keyStoreFile).inputStream.use { input ->
                ks.load(input, pwd)

                return listOf(acquireKeyPair(ks, "henry_key_pair_2003_03_17", pwd), acquireKeyPair(ks, "henry_key_pair_2003_03_22", pwd))
            }
        }

        private fun acquireKeyPair(ks: KeyStore, rsaPairName1: String, pwd: CharArray):RSAKey {
            val privateKey = ks.getKey(rsaPairName1, pwd) as RSAPrivateKey
            val publicKey = ks.getCertificate(rsaPairName1).publicKey as RSAPublicKey

            return RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(rsaPairName1)
                .keyUse(KeyUse.SIGNATURE)
                .build()
        }
    }
}