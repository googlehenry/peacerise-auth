package com.peacerise.identity.auth.config

enum class TokenScope(var value: String) {
    USER_DATA_READ("user.data.read"), USER_DATA_WRITE("user.data.write"),
    USER_PROFILE_READ("user.profile.read"), USER_PROFILE_WRITE("user.profile.write")
}