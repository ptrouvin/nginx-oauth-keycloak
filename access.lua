-- access.lua : based on https://github.com/eschwim/nginx-google-oauth
-- LICENSE: The MIT License (MIT)
-- 
-- Copyright (c) 2014 Aaron Westendorf
--
-- adaptation to Microsoft Azure
-- Author: Pascal Trouvin
--
-- History:
-- 20170330: Fix require resty.http
-- 20160208: do not expose OAUTHv2 JWT token anymore: security issue, 
--           because unable to verify the signature and thus can be manually updated to gain unauthorized access
-- 20160202: fix logout
--           export OAUTHv2 token as a cookie

-- import requirements

-- allow either cjson, or th-LuaJSON
local has_cjson, jsonmod = pcall(require, "cjson")
if not has_cjson then
  jsonmod = require "json"
end

-- Ubuntu broke the install. Puts the source in /usr/share/lua/5.1/https.lua,
-- but since the source defines itself as the module "ssl.https", after we
-- load the source, we need to grab the actual thing.
-- pcall(require,"https")
-- local https = require "ssl.https" -- /usr/share/lua/5.1/https.lua

local _debug = ngx.var.ngo_debug
if _debug == "0" or _debug == "false" then
  _debug = false;
end

local http = require "resty.http"

local uri = ngx.var.uri
local uri_args = ngx.req.get_uri_args()
if _debug then
	ngx.log(ngx.ERR,"DEBUG: uri args: "..uri.." = "..jsonmod.encode(uri_args))
	ngx.log(ngx.ERR,"DEBUG: uri args: "..ngx.var.request)
end

local scheme = ngx.var.scheme
local server_name = ngx.var.server_name
local url = scheme.."://"..(ngx.var.host .. ngx.var.uri)

-- setup some app-level vars
local tenant_id = ngx.var.ngo_tenant_id
local client_id = ngx.var.ngo_client_id
-- local client_secret = ngx.var.ngo_client_secret
local domain = ngx.var.ngo_domain
local cb_scheme = ngx.var.ngo_callback_scheme or scheme
local cb_server_name = ngx.var.ngo_callback_host or server_name
local cb_uri = ngx.var.ngo_callback_uri or uri or "/oauth"
local cb_url = cb_scheme.."://"..cb_server_name..cb_uri
local redir_url = ngx.var.ngo_callback_url or cb_scheme.."://"..cb_server_name..uri
local token_url = ngx.var.ngo_callback_token or "/token"
local auth_url = ngx.var.ngo_callback_auth or "/auth"
local signout_uri = ngx.var.ngo_callback_logout or "/signout"
local whitelist = ngx.var.ngo_whitelist
local blacklist = ngx.var.ngo_blacklist
local secure_cookies = ngx.var.ngo_secure_cookies
local token_secret = ngx.var.ngo_token_secret or "UNSET"
local set_user = ngx.var.ngo_user
local email_as_user = ngx.var.ngo_email_as_user

-- check if end with a '/'
if redir_url:sub(redir_url:len()) ~= '/' then
	redir_url = redir_url .. '/'
end

if _debug then
  ngx.log(ngx.ERR, "DEBUG: url= "..url.." scheme="..scheme.." host="..ngx.var.host.." uri="..uri.." args="..jsonmod.encode(uri_args))
end
-- Force the user to set a token secret
if token_secret == "UNSET" then
  ngx.log(ngx.ERR, "$ngo_token_secret must be set in Nginx config!")
  return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

-- See https://developers.google.com/accounts/docs/OAuth2WebServer 
-- or uri ends with /_signout
if uri == signout_uri or string.sub(uri,-string.len(signout_uri)) == signout_uri then
  ngx.header["Set-Cookie"] = {
    "OauthAccessToken=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT",
    "OauthTokenSign=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT",
    "OauthExpires=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT",
    "OauthName=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT",
    "OauthEmail=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT",
    "OauthPicture=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT"
  }

  return ngx.redirect(signout_uri .. "?redirect_uri=" .. redir_url)
end

function checkAccessControl(access_token)
  -- split and interpret access_token
  local alg, claims, sign = access_token:match('^([^.]+)[.]([^.]+)[.](.*)')
  if not alg or not claims or not sign then
    ngx.log(ngx.ERR, "BUGCHECK: checkAccessControl called with invalid data: "..access_token)
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
  end
  if _debug then
    ngx.log(ngx.ERR, "DEBUG: token split "..alg..' . '..claims..' . '..sign)
  end

  local _claims = ngx.decode_base64( claims )
  if _debug then
    ngx.log(ngx.ERR, "DEBUG: claims JSON ".._claims)
  end
  local json_claims = jsonmod.decode(_claims)
  
  return json_claims
end


-- Enforce token security and expiration
local oauth_expires = tonumber(ngx.var.cookie_OauthExpires) or 0
local oauth_email = ngx.unescape_uri(ngx.var.cookie_OauthEmail or "")
local oauth_token_sign = ngx.unescape_uri(ngx.var.cookie_OauthTokenSign or "")
local access_token = ngx.unescape_uri(ngx.var.cookie_OauthAccessToken or "")
local expected_token = ngx.encode_base64(ngx.hmac_sha1(token_secret, cb_server_name .. access_token .. oauth_email .. oauth_expires))

if oauth_token_sign == expected_token and oauth_expires and oauth_expires > ngx.time() then
  -- JWT access_token is still valid

  -- Populate the nginx 'ngo_user' variable with our Oauth username, if requested
  if set_user then
    local oauth_user, oauth_domain = oauth_email:match("([^@]+)@(.+)")
    if email_as_user then
      ngx.var.ngo_user = email
    else
      ngx.var.ngo_user = oauth_user
    end
  end
  
  -- restore OAUTH JWT token
  if not access_token then
    ngx.log(ngx.ERR, "Security failure: the OAUTH token is not set")
    return ngx.exit(400)
  end
  
  -- check for access control : groups required
  local json_claims = checkAccessControl(access_token)
  
  return
  
else
  -- No valid JWT access_token or expired

  -- Fetch the authorization code from the parameters
  -- local auth_code = uri_args["code"]
  local auth_code = uri_args.code
  -- If no access token and this isn't the callback URI, redirect to oauth
  if not auth_code then
    -- Redirect to the /oauth endpoint, request access to ALL scopes
    -- return ngx.redirect("https://accounts.google.com/o/oauth2/auth?client_id="..client_id.."&scope=email&response_type=code&redirect_uri="..ngx.escape_uri(cb_url).."&state="..ngx.escape_uri(redir_url).."&login_hint="..ngx.escape_uri(domain))
    -- https://login.windows.net/<<YOUR-AD-TENANT-ID>>/oauth2/authorize?client_id=<<GUID>>&response_type=code
    -- return ngx.redirect("https://login.windows.net/"..tenant_id.."/oauth2/authorize?client_id="..client_id.."&response_type=code&state="..ngx.escape_uri(url))
    local random = require "resty.random"
    local uuid = random.token(10)
    return ngx.redirect( auth_url .. "&redirect_uri=" .. ngx.escape_uri(redir_url) .. "&state=" .. ngx.escape_uri(redir_url) .. "&nonce=" .. random.token(10) .. "&response_mode=query&response_type=code&scope=openid")
  end

  local auth_error = uri_args["error"]

  if auth_error then
    ngx.log(ngx.ERR, "received "..auth_error.." from "..auth_url)
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
  end

  if _debug then
    ngx.log(ngx.ERR, "DEBUG: fetching token for auth code "..auth_code)
  end

  -- TODO: Switch to NBIO sockets
  -- If I get around to working luasec, this says how to pass a function which
  -- can generate a socket, needed for NBIO using nginx cosocket
  -- http://lua-users.org/lists/lua-l/2009-02/msg00251.html
  -- local res, code, headers, status = https.request(
    -- "https://accounts.google.com/o/oauth2/token",
  -- "code="..ngx.escape_uri(auth_code).."&client_id="..client_id.."&client_secret="..client_secret.."&redirect_uri="..ngx.escape_uri(cb_url).."&grant_type=authorization_code"
  -- POST /<<AD-TENANT-ID>>/oauth2/token HTTP/1.1
  -- Host: login.windows.net
  -- Content-Type: application/x-www-form-urlencoded
  -- 
  -- grant_type=authorization_code&code=<<CODE>>&redirect_uri=<<REDIRECT_URI>>&client_id=<<CLIENT_ID>>&resource=https://management.core.windows.net/
  local httpc = http.new()
  local res, err = httpc:request_uri( token_url, {
        method = "POST",
    	headers = { 
	      ["Content-Type"] = "application/x-www-form-urlencoded",
	      ["Host"] = "127.0.0.1:30240"
		  -- ["Authorization"] = "Bearer "..ngx.var.ngo_client_id
	    },
		ssl_verify = false,
		body = "code="..ngx.escape_uri(auth_code).."&redirect_uri="..ngx.escape_uri(redir_url).."&grant_type=authorization_code&client_id="..ngx.escape_uri(ngx.var.ngo_client_id).."&client_secret="..ngx.escape_uri(ngx.var.ngo_token_secret)
      })

  if not res then
    ngx.log(ngx.ERR, "failed to request: ".. err)
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
  end

  -- In this simple form, there is no manual connection step, so the body is read
  -- all in one go, including any trailers, and the connection closed or keptalive
  -- for you.

  ngx.status = res.status

  if _debug then 
    ngx.log(ngx.ERR, "DEBUG BODY: "..res.body.." headers: "..jsonmod.encode(res.headers))
  end
  
  if res.status~=200 then
    ngx.log(ngx.ERR, "received "..res.status.." : "..res.body.." from "..token_url)
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
  end

  -- use version 1 cookies so we don't have to encode. MSIE-old beware
  local json  = jsonmod.decode( res.body )
  if _debug then
    ngx.log(ngx.ERR, "DEBUG: JSON returned: "..res.body)
  end
  local access_token = json["access_token"]
  local expires = ngx.time() + json["expires_in"]
  local cookie_tail = ";version=1;path=/;Max-Age="..json["expires_in"]
  if secure_cookies == "true" then
    cookie_tail = cookie_tail..";secure"
  end

  local json_claims = checkAccessControl(access_token)
  local name = json_claims["name"] or json_claims["preferred_username"]
  local email = json_claims["email"] or json_claims["unique_name"] or json_claims["upn"] or ""
  local picture = json_claims["ipaddr"]
  
  local tokenSign = ngx.encode_base64(ngx.hmac_sha1(token_secret, cb_server_name .. access_token .. email .. expires))

  local oauth_user, oauth_domain = email:match("([^@]+)@(.+)")

  -- If no whitelist or blacklist, match on domain
  if not whitelist and not blacklist and domain then
    if oauth_domain ~= domain then
      if _debug then
        ngx.log(ngx.ERR, "DEBUG: "..email.." not in "..domain)
      end
      return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end
  end

  if whitelist then
    if not string.find(" " .. whitelist .. " ", " " .. email .. " ") then
      if _debug then
        ngx.log(ngx.ERR, "DEBUG: "..email.." not in whitelist")
      end
      return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end
  end

  if blacklist then
    if string.find(" " .. blacklist .. " ", " " .. email .. " ") then
      if _debug then
        ngx.log(ngx.ERR, "DEBUG: "..email.." in blacklist")
      end
      return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end
  end

  ngx.header["Set-Cookie"] = {
    "OauthAccessToken="..ngx.escape_uri(access_token)..cookie_tail,
    "OauthTokenSign="..ngx.escape_uri(tokenSign)..cookie_tail,
    "OauthExpires="..expires..cookie_tail,
    "OauthName="..ngx.escape_uri(name)..cookie_tail,
    "OauthEmail="..ngx.escape_uri(email)..cookie_tail,
    "OauthPicture="..ngx.escape_uri(picture)..cookie_tail
  }
  
  
  -- Populate our ngo_user variable
  if set_user then
    if email_as_user then
      ngx.var.ngo_user = email
    else
      ngx.var.ngo_user = oauth_user
    end
  end
  
  -- Redirect
  ngx.log(ngx.ERR, "Authorized "..email.."/"..name..", redirecting to "..uri_args["state"])

  return ngx.redirect(uri_args["state"]) 
end

