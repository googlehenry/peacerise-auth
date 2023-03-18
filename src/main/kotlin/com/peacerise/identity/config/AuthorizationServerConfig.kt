package com.peacerise.identity.config

import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import com.peacerise.identity.portal.enhanced.JdbcRegisteredClientRepositoryEnhanced
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.*
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.token.*
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import java.util.*


@Configuration(proxyBeanMethods = false)
class AuthorizationServerConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)
        http.getConfigurer(OAuth2AuthorizationServerConfigurer::class.java).oidc(Customizer.withDefaults())
        http.exceptionHandling {
            it.authenticationEntryPoint(LoginUrlAuthenticationEntryPoint("/login"))
        }.oauth2ResourceServer {
            it.jwt()
        }
        return http.build()
    }

    @Bean
    fun registeredClientRepository(jdbcTemplate: JdbcTemplate?): JdbcRegisteredClientRepositoryEnhanced? {
        val registeredClient: RegisteredClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("messaging-client")
            .clientSecret("{noop}secret")
            .clientName("messaging-client-app")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .redirectUri("http://127.0.0.1:8080/authorized")
            .scope("message.read")
            .scope("message.write")
            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
            .build()

        val registeredClientSiteLogin: RegisteredClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("login-client")
            .clientSecret("{noop}login-secret")
            .clientName("login-client-app")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .redirectUri("http://127.0.0.1:8080/peacerise/authorized")
            .scope("site-login.read")
            .scope("site-login.write")
            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
            .build()

        // Save registered client in db as if in-memory
        val registeredClientRepository = JdbcRegisteredClientRepositoryEnhanced(jdbcTemplate)
        registeredClientRepository.save(registeredClient)
        registeredClientRepository.save(registeredClientSiteLogin)
        return registeredClientRepository
    }
    // @formatter:on

    // @formatter:on
    @Bean
    fun authorizationService(
        jdbcTemplate: JdbcTemplate?,
        registeredClientRepository: RegisteredClientRepository?
    ): OAuth2AuthorizationService? {
        return JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository)
    }

    @Bean
    fun authorizationConsentService(
        jdbcTemplate: JdbcTemplate?,
        registeredClientRepository: RegisteredClientRepository?
    ): OAuth2AuthorizationConsentService? {
        return JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository)
    }

    @Bean
    fun jwkSource(): JWKSource<SecurityContext?>? {
        val rsaKey: RSAKey = KeyStoreConfig.loadKeyPairFromKeyStore()
        val jwkSet = JWKSet(rsaKey)
        return JWKSource { jwkSelector: JWKSelector, securityContext: SecurityContext? ->
            jwkSelector.select(
                jwkSet
            )
        }
    }

    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings? {
        return AuthorizationServerSettings.builder().build()
    }

    @Bean
    fun embeddedDatabase(): EmbeddedDatabase? {
        return EmbeddedDatabaseBuilder()
            .generateUniqueName(false)
            .setType(EmbeddedDatabaseType.H2)
            .setScriptEncoding("UTF-8")
            .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
            .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
            .addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
            .build()

    }
}