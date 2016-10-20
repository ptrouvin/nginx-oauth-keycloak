-- LICENSE: The MIT License (MIT)
-- 
-- Copyright (c) 2014 Aaron Westendorf
--
-- adaptation to Microsoft Azure
-- Author: Pascal Trouvin
--
-- History:
-- 20161020: fix '==' in cookies deletion
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
local redir_url = ngx.var.ngo_callback_url or cb_scheme.."://"..cb_server_name..uri
local signout_uri = ngx.var.ngo_callback_logout or "/signout"
ngx.log(ngx.ERR, "user logout: "..user)

-- check if end with a '/'
if redir_url:sub(redir_url:len()) ~= '/' then
	redir_url = redir_url .. '/'
end


ngx.header["Set-Cookie"] = {
"OauthAccessToken=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT",
"OauthTokenSign=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT",
"OauthExpires=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT",
"OauthName=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT",
"OauthEmail=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT",
"OauthPicture=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT"
}
return ngx.redirect(signout_uri .. "?redirect_uri=" .. redir_url)

