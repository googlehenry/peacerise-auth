package com.peacerise.identity.auth.portal

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/client")
class ClientAPIController {

    @Autowired
    lateinit var clientService: ClientService

    @RequestMapping("/list")
    fun getAllClients():List<RegisteredClient>{
        //mapOf("aaData" to )
        return clientService.getClients()
    }
}