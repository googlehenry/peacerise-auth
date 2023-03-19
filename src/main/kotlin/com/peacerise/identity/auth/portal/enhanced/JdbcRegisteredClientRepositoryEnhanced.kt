package com.peacerise.identity.auth.portal.enhanced

import org.springframework.jdbc.core.JdbcOperations
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient

class JdbcRegisteredClientRepositoryEnhanced(jdbcOperations: JdbcOperations?) : JdbcRegisteredClientRepository(jdbcOperations),
    ClientRepoEnhanced {
    override fun getAllClients(): List<RegisteredClient> {
        return jdbcOperations.query("select * from oauth2_registered_client", registeredClientRowMapper)
    }

}