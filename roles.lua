-- roles.lua : 

-- LICENSE: The MIT License (MIT)
-- 
-- Copyright (c) 2016 Pascal TROUVIN
--
-- For Microsoft Azure
-- Author: Pascal Trouvin
--
-- History:
-- 20160203: 1st version

-- import requirements

-- allow either cjson, or th-LuaJSON
local has_cjson, jsonmod = pcall(require, "cjson")
if not has_cjson then
  jsonmod = require "json"
end

local http = require "resty.http"

local scheme = ngx.var.scheme
local server_name = ngx.var.server_name
local tenant_id = ngx.var.ngo_tenant_id
local uri_args = ngx.req.get_uri_args()
local group_id = uri_args["group_id"] or ""
local user = ngx.var.cookie_OauthEmail or "UNKNOWN"
ngx.log(ngx.ERR, "user:"..user.." GROUP_REQUEST:"..group_id)
local oauth_expires = tonumber(ngx.var.cookie_OauthExpires) or 0
local oauth_email = ngx.unescape_uri(ngx.var.cookie_OauthEmail or "")
local oauth_token_sign = ngx.unescape_uri(ngx.var.cookie_OauthAccessTokenSign or "")
local access_token = ngx.unescape_uri(ngx.var.cookie_OauthAccessToken or "")
local expected_token = ngx.encode_base64(ngx.hmac_sha1(token_secret, cb_server_name .. access_token .. oauth_email .. oauth_expires))
local _debug = ngx.var.ngo_debug
if _debug == "0" or _debug == "false" then
  _debug = false;
end

function getGroupsDetails(group_id)
  local httpc = http.new()
  local res, err = httpc:request_uri("https://graph.windows.net:443/"..tenant_id.."/groups/"..group_id.."?api-version=1.0", {
    method = "GET",
    headers = { 
      ["Authorization"] = "Bearer "..access_token,
      ["Host"] = "graph.windows.net" 
    },
    ssl_verify = false
    })

  if not res then
    ngx.log(ngx.ERR, "failed to request: ".. err)
    return jsonmod.decode(err)
  end

  if _debug then 
    ngx.log(ngx.ERR, "DEBUG BODY: "..res.body.." headers: "..jsonmod.encode(res.headers))
  end

  if res.status~=200 then
    ngx.log(ngx.ERR, "received "..res.status.." : "..res.body.." from https://graph.windows.net:443/"..tenant_id.."/groups/"..group_id.."?api-version=1.0")
  end
  
  return jsonmod.decode(res.body)
end


if oauth_token_sign != expected_token or oauth_expires or oauth_expires <= ngx.time() then
  -- token invalid or expired
  ngx.log(ngx.ERR, "roles access requested while invalid token")
  return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

-- groupsData : hash table which will be sent back at the end
local groupsData={}

if string.len(group_id) == 0 then
  -- retrieve groups id from user OAUTH.access_token
  -- split and interpret access_token
  local alg, claims, sign = access_token:match('^([^.]+)[.]([^.]+)[.](.*)')
  if _debug then
    ngx.log(ngx.ERR, "DEBUG: token split "..alg..' . '..claims..' . '..sign)
  end

  local _claims = ngx.decode_base64( claims )
  if _debug then
  ngx.log(ngx.ERR, "DEBUG: claims JSON ".._claims)
  end
  local json_claims = jsonmod.decode(_claims)

  local groups = json_claims["groups"]
  if not groups then
    ngx.log(ngx.ERR, "User: "..user.." unable to retrieve GROUPS from token: ".._claims)
    return ngx.exit(400)
  end
  
  if _debug then
    ngx.log(ngx.ERR, "User: "..user.." GROUPS: "..type(groups).." = "..jsonmod.encode(groups))
  end
  
  for i=1,#groups do
    local gid=groups[i]
    groupsData[gid]=getGroupsDetails(gid)
  end
else
  groupsData[groupd_id]=getGroupsDetails(group_id)
end

if not uri_args["as_text"] then
  ngx.header["Content-Type"] = {"application/x-json"}
end
ngx.say(jsonmod.encode(groupsData))

