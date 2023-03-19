package com.peacerise.identity.auth.portal.enhanced

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient

interface ClientRepoEnhanced {
    fun getAllClients():List<RegisteredClient>
}