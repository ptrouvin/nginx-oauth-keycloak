-- LICENSE: The MIT License (MIT)
-- 
-- Copyright (c) 2014 Aaron Westendorf
--
-- adaptation to Microsoft Azure
-- Author: Pascal Trouvin
--
-- History:
-- 20160208: do not expose OAUTHv2 JWT token anymore: security issue, 
--           because unable to verify the signature and thus can be manually updated to gain unauthorized access
-- 20160202: fix logout
--           export OAUTHv2 token as a cookie

-- import requirements

-- allow either cjson, or th-LuaJSON
local scheme = ngx.var.scheme
local server_name = ngx.var.server_name
local client_id = ngx.var.ngo_client_id
local user = ngx.var.cookie_OauthEmail or "UNKNOWN"
ngx.log(ngx.ERR, "user logout: "..user)


ngx.header["Set-Cookie"] = "OauthAccessToken=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT"
-- https://login.microsoftonline.com/common/oauth2/logout?post_logout_redirect_uri=https%3a%2f%2fportal.azure.com%2f&client_id=c44b4083-3bb0-49c1-b47d-974e53cbdf3c&redirect_uri=https%3a%2f%2fportal.azure.com%2fsignin%2findex&site_id=501430&prompt=select_account
return ngx.redirect("http://127.0.0.1:30240/auth/realms/nginx-keycloak-POC/protocol/openid-connect/logout?redirect_uri=http://127.0.0.1:30240/")

