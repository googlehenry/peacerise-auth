package com.peacerise.identity.auth.config

import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import com.peacerise.identity.auth.extend.proxybyapp.OAuth2ResourceAdminAppProxyAuthenticationProvider.PROXY_BY_APP
import com.peacerise.identity.auth.extend.proxybyuser.OAuth2ResourceAdminUserProxyAuthenticationProvider.PROXY_BY_USER
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames
import org.springframework.security.oauth2.jwt.JwsHeader
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.token.*

@Configuration
class JwtTokenConfig {
    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext?>): JwtDecoder {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
    }

    @Bean
    fun jwtEncoder(jwkSource: JWKSource<SecurityContext?>): JwtEncoder {
        return NimbusJwtEncoder(jwkSource)
    }

    @Bean
    fun tokenGenerator(
        jwtEncoder: JwtEncoder,
        jwtCustomizer: OAuth2TokenCustomizer<JwtEncodingContext>
    ): OAuth2TokenGenerator<*> {
        val jwtGenerator = JwtGenerator(jwtEncoder)
        jwtGenerator.setJwtCustomizer(jwtCustomizer)
        val accessTokenGenerator = OAuth2AccessTokenGenerator()
        val refreshTokenGenerator = OAuth2RefreshTokenGenerator()
        return DelegatingOAuth2TokenGenerator(
            jwtGenerator, accessTokenGenerator, refreshTokenGenerator
        )
    }

    @Bean
    fun jwtCustomizer(): OAuth2TokenCustomizer<JwtEncodingContext>? {
        return OAuth2TokenCustomizer { context: JwtEncodingContext ->
            val headers: JwsHeader.Builder = context.jwsHeader
            val claims = context.claims
            val scopes = context.authorizedScopes.map { it }.toMutableSet()


            val principal = context.getPrincipal<Authentication>()
            if (context.tokenType == OAuth2TokenType.ACCESS_TOKEN) {
                // Customize headers/claims for access_token
//                headers.header("customerHeader", "这是一个自定义header")
                //claims.claim("authorities", principal.authorities.map { it.authority })
                principal.authorities.map { it.authority }.firstOrNull { it.startsWith("operator_") }?.let {
                    claims.claim("operator", it)
                }
            } else if (context.tokenType.value == OidcParameterNames.ID_TOKEN) {
                // Customize headers/claims for id_token
            }

            if(context.authorizationGrantType==AuthorizationGrantType.CLIENT_CREDENTIALS){
                scopes.add("DEFAULT")
            }

            claims.claim(OAuth2ParameterNames.SCOPE, scopes)

            val type = when (context.authorizationGrantType) {
                AuthorizationGrantType.CLIENT_CREDENTIALS -> "APP_TOKEN"
                AuthorizationGrantType(PROXY_BY_APP) -> "UT_PROXY_BY_APP"
                AuthorizationGrantType(PROXY_BY_USER) -> "UT_PROXY_BY_USER"
                else -> "USER_TOKEN"
            }
            claims.claim("type", type)
        }
    }
}