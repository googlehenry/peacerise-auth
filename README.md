
### API Examples:
 1. Get app token
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