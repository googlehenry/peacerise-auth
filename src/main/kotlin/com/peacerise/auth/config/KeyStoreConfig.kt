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
        fun loadKeyPairFromKeyStore(): RSAKey {
            val ks = KeyStore.getInstance("pkcs12");
            val pwd = "123test321".toCharArray()
            val rsaPairName = "henry_key_pair_2003_03_17"
            val keyStoreFile = "/rsa-keys/henry_key_store.pkcs12.jks"
            ClassPathResource(keyStoreFile).inputStream.use { input ->

                ks.load(input, pwd)

                val privateKey = ks.getKey(rsaPairName, pwd) as RSAPrivateKey
                val publicKey = ks.getCertificate(rsaPairName).publicKey as RSAPublicKey

                return RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(UUID.randomUUID().toString())
                    .keyUse(KeyUse.SIGNATURE)
                    .build()
            }

        }
    }
}