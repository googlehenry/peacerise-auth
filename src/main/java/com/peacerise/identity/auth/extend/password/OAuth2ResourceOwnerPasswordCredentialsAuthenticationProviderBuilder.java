package com.peacerise.identity.auth.extend.password;

import com.peacerise.identity.auth.extend.password.utils.OAuth2ConfigurerUtils;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

public final class OAuth2ResourceOwnerPasswordCredentialsAuthenticationProviderBuilder {

    private HttpSecurity httpSecurity;
    private UserDetailsService userDetailsService;
    private PasswordEncoder passwordEncoder;

    public OAuth2ResourceOwnerPasswordCredentialsAuthenticationProviderBuilder(
            HttpSecurity httpSecurity, UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.httpSecurity = httpSecurity;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }


    public OAuth2ResourceOwnerPasswordCredentialsAuthenticationProvider build() {
        OAuth2AuthorizationService authorizationService = OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity);
        OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator = OAuth2ConfigurerUtils.getTokenGenerator(httpSecurity);

        OAuth2ResourceOwnerPasswordCredentialsAuthenticationProvider resourceOwnerPasswordCredentialsAuthenticationProvider =
                new OAuth2ResourceOwnerPasswordCredentialsAuthenticationProvider(authorizationService, tokenGenerator,
                        userDetailsService, passwordEncoder);
        return resourceOwnerPasswordCredentialsAuthenticationProvider;
    }
}
