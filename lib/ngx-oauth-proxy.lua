---------
-- Proxy script for OAuth 2.0.

local config  = require 'ngx-oauth.config'
local Cookies = require 'ngx-oauth.Cookies'
local either  = require 'ngx-oauth.either'
local httpc  = require 'ngx-oauth.http_client'
local nginx   = require 'ngx-oauth.nginx'
local oauth   = require 'ngx-oauth.oauth2'
local util   = require 'ngx-oauth.util'

local log    = nginx.log
local par    = util.partial

local fail_with_oaas_error = par(nginx.fail, 503, "Authorization server error: %s")
local get_or_fail = par(either, fail_with_oaas_error, util.id)

local function write_auth_header (access_token)
  ngx.req.set_header('Authorization', 'Bearer '..access_token)
end


local conf, errs = config.load()
if errs then
  return nginx.fail(500, 'OAuth proxy error: %s', errs)
end

local cookies = Cookies(conf)
local access_token = cookies.get_access_token()
local plugin = nil

if conf.plugin then
  plugin = require(conf.plugin)
end

local function trigger_before_access()
  if plugin then
    local before_access = plugin.before_access

    if not util.is_empty(before_access) then
      before_access(ngx, nginx, get_or_fail(httpc.get_for_json(conf.userinfo_url, access_token), access_token))
    end
  end
end

-- Cookie with access token found; set Authorization header and we're done.
if access_token then
  trigger_before_access()
  write_auth_header(access_token)

-- Cookie with refresh token found; refresh token and set Authorization header.
elseif cookies.get_refresh_token() then
  log.info('refreshing token for user: %s', cookies.get_username())

  either (
    function(err)
      nginx.fail(503, 'Authorization server error: %s', err)
    end,
    function(token)
      trigger_before_access()
      cookies.add_token(token)
      write_auth_header(token.access_token)
    end,
    oauth.request_token('refresh_token', conf, cookies.get_refresh_token())
  )

-- Neither access token nor refresh token found; bad luck, return HTTP 401.
else
  if plugin then
    local on_forbidden = plugin.on_forbidden

    if not util.is_empty(on_forbidden) then
      on_forbidden(ngx, nginx)
    end
  end

  ngx.header['WWW-Authenticate'] = 'Bearer error="unauthorized"'
  nginx.fail(401, 'No access token provided.')
end
