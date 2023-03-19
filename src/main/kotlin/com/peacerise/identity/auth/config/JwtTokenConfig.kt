package com.peacerise.identity.auth.config

import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetails
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
    fun tokenGenerator(jwtEncoder: JwtEncoder, jwtCustomizer: OAuth2TokenCustomizer<JwtEncodingContext>): OAuth2TokenGenerator<*> {
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
            val scopes = context.authorizedScopes


            val principal = context.getPrincipal<Authentication>()
            if (context.tokenType == OAuth2TokenType.ACCESS_TOKEN) {
                // Customize headers/claims for access_token
//                headers.header("customerHeader", "这是一个自定义header")
                //claims.claim("authorities", principal.authorities.map { it.authority })
            } else if (context.tokenType.value == OidcParameterNames.ID_TOKEN) {
                // Customize headers/claims for id_token
            }
            claims.claim(OAuth2ParameterNames.SCOPE, scopes)
            claims.claim("type", if(context.authorizationGrantType== AuthorizationGrantType.CLIENT_CREDENTIALS) "APP_TOKEN" else "USER_TOKEN")
        }
    }
}