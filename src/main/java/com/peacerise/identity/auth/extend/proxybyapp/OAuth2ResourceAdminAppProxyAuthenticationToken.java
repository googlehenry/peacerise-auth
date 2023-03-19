package com.peacerise.identity.auth.extend.proxybyapp;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
public class OAuth2ResourceAdminAppProxyAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
    private final String username;
    private final Set<String> scopes;

    public OAuth2ResourceAdminAppProxyAuthenticationToken(String username, Authentication clientPrincipal,
                                                          @Nullable Set<String> scopes, @Nullable Map<String, Object> additionalParameters) {
        super(AuthorizationGrantType.PASSWORD, clientPrincipal, additionalParameters);
        Assert.hasText(username, "username cannot be empty");
        this.username = username;
        this.scopes = Collections.unmodifiableSet(
                scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
    }
    public String getUsername() {
        return this.username;
    }

    @Nullable
    public String getPassword() {
        return null;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }
}