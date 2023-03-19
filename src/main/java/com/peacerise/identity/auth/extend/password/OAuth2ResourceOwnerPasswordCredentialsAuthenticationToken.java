package com.peacerise.identity.auth.extend.password;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
public class OAuth2ResourceOwnerPasswordCredentialsAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
    private final String username;
    private final String password;
    private final Set<String> scopes;

    public OAuth2ResourceOwnerPasswordCredentialsAuthenticationToken(String username, String password, Authentication clientPrincipal,
                                                                     @Nullable Set<String> scopes, @Nullable Map<String, Object> additionalParameters) {
        super(AuthorizationGrantType.PASSWORD, clientPrincipal, additionalParameters);
        Assert.hasText(username, "username cannot be empty");
        Assert.hasText(username, "password cannot be empty");
        this.username = username;
        this.password = password;
        this.scopes = Collections.unmodifiableSet(
                scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
    }
    public String getUsername() {
        return this.username;
    }

    @Nullable
    public String getPassword() {
        return this.password;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }
}