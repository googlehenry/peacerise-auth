package com.peacerise.identity.auth.portal

import com.peacerise.identity.auth.portal.enhanced.JdbcRegisteredClientRepositoryEnhanced
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.stereotype.Service

@Service
class ClientService {
    @Autowired
    lateinit var registeredClientRepository: JdbcRegisteredClientRepositoryEnhanced


    fun save(registedClient: RegisteredClient){
        registeredClientRepository.save(registedClient)
    }

    fun getClient(clientId:String):RegisteredClient?{
        return registeredClientRepository.findByClientId(clientId)
    }

    fun getClients():List<RegisteredClient>{
        return registeredClientRepository.getAllClients()
    }
}