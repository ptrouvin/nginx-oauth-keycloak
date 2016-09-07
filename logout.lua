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
-- resty-session https://github.com/bungle/lua-resty-session
local session=require "resty.session".new()
local scheme = ngx.var.scheme
local server_name = ngx.var.server_name
local client_id = ngx.var.ngo_client_id
local user = ngx.var.cookie_OauthEmail or "UNKNOWN"
ngx.log(ngx.ERR, "user logout: "..user)

-- destroy associated web session
session:open()
session:destroy()

ngx.header["Set-Cookie"] = "OauthAccessToken=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT"
-- https://login.microsoftonline.com/common/oauth2/logout?post_logout_redirect_uri=https%3a%2f%2fportal.azure.com%2f&client_id=c44b4083-3bb0-49c1-b47d-974e53cbdf3c&redirect_uri=https%3a%2f%2fportal.azure.com%2fsignin%2findex&site_id=501430&prompt=select_account
return ngx.redirect("https://login.microsoftonline.com/common/oauth2/logout?post_logout_redirect_uri="..ngx.escape_uri(scheme.."://"..server_name).."&client_id="..client_id.."&redirect_uri="..ngx.escape_uri(scheme.."://"..server_name))
