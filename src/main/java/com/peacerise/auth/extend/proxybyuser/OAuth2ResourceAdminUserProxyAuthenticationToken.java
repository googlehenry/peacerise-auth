package com.peacerise.auth.extend.proxybyuser;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
public class OAuth2ResourceAdminUserProxyAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    private final String username;
    private final String password;

    private final String targetUser;
    private final Set<String> scopes;

    public OAuth2ResourceAdminUserProxyAuthenticationToken(String username, String password, String targetUser, Authentication clientPrincipal,
                                                           @Nullable Set<String> scopes, @Nullable Map<String, Object> additionalParameters) {
        super(AuthorizationGrantType.PASSWORD, clientPrincipal, additionalParameters);
        Assert.hasText(username, "username cannot be empty");
        Assert.hasText(password, "password cannot be empty");
        Assert.hasText(targetUser, "targetUser cannot be empty");
        this.username = username;
        this.password = password;
        this.targetUser = targetUser;
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

    public String getTargetUser(){return this.targetUser;}

    public Set<String> getScopes() {
        return this.scopes;
    }
}