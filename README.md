### Oauth2.0 四种模式
复杂程度由大至小：授权码模式 > 隐式授权模式(废止) > 密码模式(废止) > 客户端模式

#### 查看App中hardcoded clients
```agsl
http://127.0.0.1:9000/view/clients
```

#### API Examples:
 1. client_credential (Get app token)
```

$ curl -ik -X POST localhost:9000/oauth2/token?grant_type=client_credentials --header "Content-Type: application/x-www-form-urlencoded" --header "Authorization: Basic bWVzc2FnaW5nLWNsaWVudDpzZWNyZXQ="
HTTP/1.1 200
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Date: Fri, 17 Mar 2023 12:33:30 GMT

{"access_token":"eyJraWQiOiJjNDM5NDI5ZC05Mjg2LTQ0NjAtOTRlMy0xNDc0OGJmMTVlYjQiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtZXNzYWdpbmctY2xpZW50IiwiYXVkIjoibWVzc2FnaW5nLWNsaWVudCIsIm5iZiI6MTY3OTA1NjQxMCwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAwIiwiZXhwIjoxNjc5MDU2NzEwLCJpYXQiOjE2NzkwNTY0MTB9.0S614GKHfPK9boyoy9ZjZDnWzY7Fkq8mO2H9xUPlUHk5auXiJEPa92023Y_LuOApAPOCar22nsqJXSq8-0PRA8LKRRdQLFMHA2xp7WfAVZ78Id2FqJB0wE21E66BGQtm1VpNIEszkJts3tbGpX04k5_6mOMlCWLjOLMLJEID2Kage_PsiNpBu-3ULJLxt4k86zM0btiK6xkhiAvpsfWXXx6qVlM507vN4jFgbbYUATxebIEU2rEIXzP2vAJG4k4IHGdP4tGhBRcixQC2N5Y3h2f3vDoiH-G_2zwxCuwFNbhhk7q0ZHpsmJGm-MyKnUIt0B5OhvYtwl_axlu4mtQPvg","token_type":"Bearer","expires_in":299}


```

2. authorization_code (get user token) 注意redirect_uri全程和代码/DB中保持一致. client_id必须提前注册.
```
in browser:
1.
http://127.0.0.1:9000/oauth2/authorize?response_type=code&client_id=messaging-client&scope=message.read&redirect_uri=http://127.0.0.1:8080/authorized

2.
http://127.0.0.1:8080/authorized?code=h3PFZBCG0iF9scftzibQrLkmMmmqxNVuDcTf8nOPeGOpmXxM8Mrxj_dXwSKKmwOTeGjc49tqPbcdRqmtGvlEZLoQdExLIzFvItIqowdc1Ag0aKwOOYRhES2JgA0OxxEd

```
```
3.
curl --location '127.0.0.1:9000/oauth2/token' \
--header 'Authorization: Basic bWVzc2FnaW5nLWNsaWVudDpzZWNyZXQ=' \
--form 'code="PpUeRjU7vA3pawyxe_zZH6jiopEFhxAyWst1aAiwCwUJRUAJ25qqooUIKHPSvDQOqumjdEXwFxew-MPF8gGPA_9RG_0kCGKl2JtTa3vrGrltQACoD9ZaoVEc1xJApYcq"' \
--form 'grant_type="authorization_code"' \
--form 'redirect_uri="http://127.0.0.1:8080/authorized"'

resp:
{
    "access_token": "eyJraWQiOiIwMjBiYWRmYy04OWFlLTQ3MjAtYWQ1Ni0zYzExNzg2ZTkzZTUiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImF1ZCI6Im1lc3NhZ2luZy1jbGllbnQiLCJuYmYiOjE2NzkxMTAwNjUsInNjb3BlIjpbIm1lc3NhZ2UucmVhZCJdLCJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjkwMDAiLCJleHAiOjE2NzkxMTAzNjUsImlhdCI6MTY3OTExMDA2NX0.jd-G87YE8mhoZPRmCBFPZMUyZJnxYafNvzMk-luCLDGVf0-MksR8OMOkIisVzm8-TuDC6r2OhKrkOSf5YCADUtR8VjGZEXenCfn--YJCDKfFl2L3OYr5SGYrq2Qwqp1I8COBSnoEn4XDqMj1p1gGYqSnAM0MmYPpo4xi7h1OYFVm2L6AXz2aUhCLlAZHXFU6gXn43FFkM3vczQoCKChuMJu-j6-K-tHP0V5G5vvsxyH3sERDi5kE3GnnQ_Y8m21BUz1Yi5cQSTn5_DaYU6uDlPxFb28wrg6hRjhNPGQp5r6P8vOe-RaBXVJIGHHZXJyvn2eoh4VaO1bSisw5uMTglg",
    "refresh_token": "9auF2_nWoHk1yMXndg2Za2Wvgk23WGzHyFKte9hmr5Fzb4jZCg45ISaCjNt2IasPKSTS0QF2vCINM6C0ozAQzQkFggRlIq85iomuZfzrTPVFBrWhLbuRkLsuiUBGZncY",
    "scope": "message.read",
    "token_type": "Bearer",
    "expires_in": 300
}

```

3. Customized Password mode (注意自定义类是java source folder下面的, 不要放到kotlin source folder中, 运行时缺少class)
```agsl
curl --location 'localhost:9000/oauth2/token' \
--header 'Authorization: Basic bG9naW4tY2xpZW50OmxvZ2luLXNlY3JldA==' \
--form 'grant_type="password"' \
--form 'username="user1"' \
--form 'password="password"' \
--form 'scope="user.data.read"'

{
    "access_token": "eyJraWQiOiJiMzg2NzIzYy0zMjhkLTRmMWEtOTQxNC04Yjk2Y2NiN2JhNGIiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImF1ZCI6ImxvZ2luLWNsaWVudCIsIm5iZiI6MTY3OTIwNTYwOSwic2NvcGUiOlsidXNlci5kYXRhLnJlYWQiXSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAwIiwiZXhwIjoxNjc5MjEyODA5LCJ0eXBlIjoiVVNFUl9UT0tFTiIsImlhdCI6MTY3OTIwNTYwOX0.VR7xgV6-fi40WT2ErqU3nh5dwcsufCe76eVX5FNS-SUQBYnJV-BJDjbqGpSpwnFzwahyJW5_vD5knLPaxbo5t7EKl2VYJ89m6wmbv6dhrZJF4SpslK-Ckh50-Pl22JQgC4EGKKKRNSFB3RX0bn3xSYbaIPu86dKJeQah1OKgxupT5w_V3v_F0fwyqJwrCndMhAKOZxjLnfydSVXqSwNGOog-eFhqnmJfeZQuM6L3fm8PErV3slLEL6i3N94Vt-Itg0qakG9yB5M4Hdfn2VxXW9A08XOE-Fm1EEEaARDHGgsVL1XNerfJzMXtCR5v1ufzfbLwpxRCt8xHgSIaDDDEBg",
    "expires_in": 7200,
    "refresh_token": "82Y3nWqcqEZLZA7KZ7a69AZdTNKZkq127LQwqgQz7DJhZpjRn22VDGB2epaIo5jnSX3N8TKnPZF6Xz-Ix1PiJ6mh___dmyY5b7T2oKfUV5pE-mLQQGVsPr5Iw72jyfRg",
    "scope": "user.data.read",
    "token_type": "Bearer"
}
```


#### Spring Security Architecture (https://docs.spring.io/spring-security/reference/servlet/architecture.html)

```agsl
Security Filters
The Security Filters are inserted into the FilterChainProxy with the SecurityFilterChain API. The order of Filter instances matters. It is typically not necessary to know the ordering of Spring Security’s Filter instances. However, there are times that it is beneficial to know the ordering.

The following is a comprehensive list of Spring Security Filter ordering:
---------
ForceEagerSessionCreationFilter
ChannelProcessingFilter
WebAsyncManagerIntegrationFilter
SecurityContextPersistenceFilter
HeaderWriterFilter
CorsFilter
CsrfFilter
LogoutFilter
OAuth2AuthorizationRequestRedirectFilter
Saml2WebSsoAuthenticationRequestFilter
X509AuthenticationFilter
AbstractPreAuthenticatedProcessingFilter
CasAuthenticationFilter
OAuth2LoginAuthenticationFilter
Saml2WebSsoAuthenticationFilter
UsernamePasswordAuthenticationFilter
DefaultLoginPageGeneratingFilter
DefaultLogoutPageGeneratingFilter
ConcurrentSessionFilter
DigestAuthenticationFilter
BearerTokenAuthenticationFilter
BasicAuthenticationFilter
RequestCacheAwareFilter
SecurityContextHolderAwareRequestFilter
JaasApiIntegrationFilter
RememberMeAuthenticationFilter
AnonymousAuthenticationFilter
OAuth2AuthorizationCodeGrantFilter
SessionManagementFilter
ExceptionTranslationFilter
FilterSecurityInterceptor
SwitchUserFilter
---------
```