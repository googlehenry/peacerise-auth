package com.peacerise.identity.auth.portal

import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.servlet.ModelAndView

@Controller
@RequestMapping("/view")
class ClientViewController {

    @RequestMapping("/clients")
    fun clients():ModelAndView{
        return ModelAndView("view_clients")
    }
}