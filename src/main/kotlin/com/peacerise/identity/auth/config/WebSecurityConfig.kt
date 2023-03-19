package com.peacerise.identity.auth.config

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
class WebSecurityConfig {


    @Bean
    fun defaultSecurityFilterChain(http:HttpSecurity): SecurityFilterChain {
        http
            .csrf()
            .disable()
            .authorizeHttpRequests()
            .requestMatchers("/h2/**")
            .permitAll()
            .requestMatchers("/login")
            .permitAll()
            .anyRequest()
            .authenticated()

        http.formLogin(Customizer.withDefaults())
        http.headers().frameOptions().sameOrigin()

        return http.build()
    }

    @Bean
    fun users():UserDetailsService{
        return InMemoryUserDetailsManager(User.withDefaultPasswordEncoder().username("user1").password("password").roles("USER").build())
    }
}