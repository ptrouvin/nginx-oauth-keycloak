-- LICENSE: The MIT License (MIT)
-- 
-- Copyright (c) 2014 Aaron Westendorf
--
-- adaptation to Microsoft Azure
-- Author: Pascal Trouvin
--
-- History:
-- import requirements
	# for debug purpose                                                  ------ DEBUG
    location ~ /dns/(?<url>.*) {
          content_by_lua_block {
                local url=ngx.var.url;
                ngx.say('<pre>hello url='..url..'\n');
                local resolver = require "resty.dns.resolver"
                local r, err = resolver:new{
                    -- nameservers = {"8.8.8.8", {"8.8.4.4", 53} },
                    nameservers = {"168.63.129.16" },
                    retrans = 5,  -- 5 retransmissions on receive timeout
                    timeout = 2000,  -- 2 sec
                }

                if not r then
                    ngx.say("failed to instantiate the resolver: ", err)
                    return
                end

                local answers, err = r:query(url)
                if not answers then
                    ngx.say("failed to query the DNS server: ", err)
                    return
                end

                if answers.errcode then
                    ngx.say("server returned error code: ", answers.errcode,
                            ": ", answers.errstr)
                end

                for i, ans in ipairs(answers) do
                    ngx.say(ans.name, " ", ans.address or ans.cname,
                            " type:", ans.type, " class:", ans.class,
                            " ttl:", ans.ttl)
                end
                ngx.say('\n');
          }
        }
        location ~ /url/(?<url>.*) {
                content_by_lua_block {
                        -- For simple singleshot requests, use the URI interface.
                        local has_cjson, jsonmod = pcall(require, "cjson")
                        if not has_cjson then
                          jsonmod = require("json")
                        end

                        local http = require("resty.http")
                        ngx.log(ngx.ERR, "DEBUG: http:"..type(http))
                        local hc = http:new()
                        if hc then
                                ngx.log(ngx.ERR, "DEBUG: hc:"..jsonmod.encode(hc))
                        else
                                ngx.log(ngx.ERR, "DEBUG: hc: NIL")
                        end

                        local _url = ngx.var.url
                        if not _url then
                                _url="https://login.windows.net:443"
                        end
                        ngx.log(ngx.ERR, "DEBUG: ".._url)
                        local ok, code, headers, status, body  = hc:request {
                                url = url,
                --- proxy = "http://127.0.0.1:8888",
                --- timeout = 3000,
                --- scheme = 'https',
                method = "POST", -- POST or GET
                -- add post content-type and cookie
                headers = { Cookie = {"ABCDEFG"}, ["Content-Type"] = "application/x-www-form-urlencoded" },
                body = "uid=1234567890",
            }

            ngx.say(ok)
            ngx.say(code)
            ngx.say(body)
                }
        }
