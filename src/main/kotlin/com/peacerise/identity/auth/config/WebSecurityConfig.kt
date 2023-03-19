package com.peacerise.identity.auth.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain

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
        return InMemoryUserDetailsManager(
            User.builder().username("user1").password("{noop}password").roles("USER").build(),
            User.builder().username("user2").password("{noop}password").roles("USER").build()
            )
    }
    @Bean
    fun passwordEncoder(): PasswordEncoder{
        return  PasswordEncoderFactories.createDelegatingPasswordEncoder()
    }
}