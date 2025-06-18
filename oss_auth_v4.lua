local resty_hmac = require('resty.hmac')
local resty_sha256 = require('resty.sha256')
local str = require('resty.string')
local oss_region = os.getenv("OSS_REGION") or "cn-beijing"
local SIGN_ALGORITHM = "OSS4-HMAC-SHA256"

-- has been sorted in alphabetical order
local signed_subresources = {
   'acl',
   'append',
   'bucketInfo',
   'cname',
   'commitTransition',
   'comp',
   'cors',
   'delete',
   'lifecycle',
   'location',
   'logging',
   'mime',
   'notification',
   'objectInfo',
   'objectMeta',
   'partData',
   'partInfo',
   'partNumber',
   'policy',
   'position',
   'referer',
   'replication',
   'replicationLocation',
   'replicationProgress',
   'requestPayment',
   'response-cache-control',
   'response-content-disposition',
   'response-content-encoding',
   'response-content-language',
   'response-content-type',
   'response-expires',
   'restore',
   'security-token',
   'tagging',
   'torrent',
   'uploadId',
   'uploads',
   'versionId',
   'versioning',
   'versions',
   'website'
}

local function string_startswith(s, start)
   return string.sub(s, 1, string.len(start)) == start
end

local function string_ends(String,End)
   return End=='' or string.sub(String,-string.len(End))==End
end

local function string_split(str, delimiter)
    local result = {}
    local pattern = string.format("([^%s]+)", delimiter)
    for match in string.gmatch(str, pattern) do
        table.insert(result, match)
    end
    return result
end


local function get_credentials()
    local access_key = os.getenv('OSS_AUTH_ID')
    local secret_key = os.getenv('OSS_AUTH_KEY')

    if not access_key or not secret_key then
        ngx.log(ngx.ERR, "Missing OSS credentials")
        return nil
    end

    return {
        access_key = access_key,
        secret_key = secret_key
    }
end


-- local function calc_sign(key, method, md5, type_, date, oss_headers, resource)
--     -- string_to_sign:
--     -- method + '\n' + content_md5 + '\n' + content_type + '\n'
--     -- + date + '\n' + canonicalized_oss_headers + canonicalized_resource
--     local sign_str = string.format('%s\n%s\n%s\n%s\n%s%s',
--     method, md5, type_,
--     date, oss_headers, resource)
--     ngx.log(ngx.ERR, "SignStr:", sign_str, "\n")
--     local sign_result = ngx.encode_base64(ngx.hmac_sha1(key, sign_str))
--     return sign_result, sign_str
-- end

local function string_starts(String,Start)
   return string.sub(String,1,string.len(Start))==Start
end

local function string_ends(String,End)
   return End=='' or string.sub(String,-string.len(End))==End
end

local function get_iso8601_basic(timestamp)
  return tostring(os.date('!%Y%m%dT%H%M%SZ', timestamp))
end

local function get_iso8601_basic_short(timestamp)
  return tostring(os.date('!%Y%m%d', timestamp))
end

local function get_sha256_digest(s)
  local h = resty_sha256:new()
  h:update(s or '')
  return str.to_hex(h:final())
end


-- 判断是否为默认签名头
-- @param key string
-- @return boolean
local function is_default_sign_header(key)
    if not key then
        return false
    end
    if string.sub(key, 1, 6) == "x-oss-" then
        return true
    end
    if key == "content-type" or key == "content-md5" then
        return true
    end
    return false
end

local function is_sign_header(key, additional_headers)
    if not key then
        return false
    end
    if string.sub(key, 1, 6) == "x-oss-" then
        return true
    end
    if key == "content-type" or key == "content-md5" then
        return true
    end
    if additional_headers then
        -- 兼容 additional_headers 是数组或 set
        if additional_headers[key] then
            return true
        end
        for _, v in ipairs(additional_headers) do
            if v == key then
                return true
            end
        end
    end
    return false
end



local function get_canonical_query_string()
   local args = ngx.req.get_uri_args()
   -- lower keys
   local keys = {}
   for k, v in pairs(args) do
      keys[k:lower()] = v
   end
   -- make resource string
   local s = ''
   local sep = '?'
   for i, k in ipairs(signed_subresources) do
      local v = keys[k]
      if v then
         -- sub table
         v = type(v) == 'table' and v[1] or v
         s = s .. string.format("%s%s=%s", sep, k, v)
         sep = '&'
      end
   end
   return s
end

-- local function get_canon_resource()
--    resource = ''
--    object = ngx.unescape_uri(ngx.var.uri)
--    sub = get_canon_sub_resource()
--    return string.format("/%s%s%s", ngx.var.oss_bucket, object, sub)
-- end

local function get_canonical_headers(additional_headers)
   local headers = ngx.req.get_headers()
   local keys = {}
   for k, v in pairs(headers) do
      local lower_key = string.lower(k)
      if is_sign_header(lower_key, additional_headers) then
         -- if type(v) ~= 'string' then return nil end
         table.insert(keys, k)
      end
   end
   -- sorted in alphabetical order
   table.sort(keys)
   local result = {}
   for _, key in ipairs(keys) do
      table.insert(result, key .. ':' .. headers[key] .. '\n')
   end
   return table.concat(result)
end

local function get_cred_scope(timestamp, region, service)
    return get_iso8601_basic_short(timestamp)
            .. '/' .. region
            .. '/' .. service
            .. '/aliyun_v4_request'
end


local function get_addtional_headers_keys(request_headers, additional_headers)
    local keys = {}

    if not additional_headers or not request_headers then
        return keys
    end

    for _, k in ipairs(additional_headers) do
        local lk = string.lower(k)
        if is_default_sign_header(lk) then
            -- 跳过默认签名头
        elseif request_headers and request_headers[lk] and #request_headers[lk] > 0 then
            table.insert(keys, lk)
        end
    end

    table.sort(keys)
    return keys
end

local function get_canonical_additional_headers(request_headers, additional_headers)
    local canonical_additional_headers = ""
    local addtional_headers_keys=get_addtional_headers_keys(request_headers, additional_headers)
    if addtional_headers_keys then
        for _, k in ipairs(addtional_headers_keys) do
            canonical_additional_headers = canonical_additional_headers .. ';' .. k
        end
    end
    return canonical_additional_headers
end

local function get_derived_signing_key(keys, timestamp, region, service)
  local h_date = resty_hmac:new('aliyun_v4' .. keys['secret_key'], resty_hmac.ALGOS.SHA256)
  h_date:update(get_iso8601_basic_short(timestamp))
  local k_date = h_date:final()

  local h_region = resty_hmac:new(k_date, resty_hmac.ALGOS.SHA256)
  h_region:update(region)
  local k_region = h_region:final()

  local h_service = resty_hmac:new(k_region, resty_hmac.ALGOS.SHA256)
  h_service:update(service)
  local k_service = h_service:final()

  local h = resty_hmac:new(k_service, resty_hmac.ALGOS.SHA256)
  h:update('aliyun_v4_request')
  return h:final()
end

local function get_signature(derived_signing_key, string_to_sign)
  local h = resty_hmac:new(derived_signing_key, resty_hmac.ALGOS.SHA256)
  h:update(string_to_sign)
  return h:final()
end

local function escape_simple(s)
    return string.gsub(s, "/", "%%2F")
end

local function get_hashed_canonical_request(timestamp, host, uri, body_digest)
    local canonical_uri=''
    local canonical_query=''

    if string_ends(uri, '/')
    then
        canonical_uri=string.format("/%s/", ngx.var.oss_bucket)
        -- UriEncode("marker")+"="+UriEncode("someMarker")+"&"+UriEncode("max-keys")+"="+UriEncode("20")+"&"+UriEncode("prefix")+"="+UriEncode("somePrefix")
--         canonical_query=string.format('delimiter=%s&prefix=%s', "/", uri)
        canonical_query=string.format('delimiter=%s&prefix=%s', ngx.escape_uri("/"), ngx.escape_uri(uri))
        ngx.log(ngx.INFO,"canonical_query:\n" .. canonical_query)
    else
        canonical_uri=string.format("/%s/%s",ngx.var.oss_bucket, uri)
        canonical_query=get_canonical_query_string()
    end

   local canonical_headers=get_canonical_headers(nil)
   local canonical_additional_headers=get_canonical_additional_headers(ngx.req.get_headers(), nil)
   local canonical_request=string.format("%s\n%s\n%s\n%s\n%s\n%s",
        ngx.var.request_method:upper(),
        canonical_uri,
        canonical_query,
        canonical_headers,
        canonical_additional_headers,
        body_digest
    )

    local xx=string.format("[%s]\n[%s]\n[%s]\n[%s]\n[%s]\n[%s]",
        ngx.var.request_method:upper(),
        canonical_uri,
        canonical_query,
        canonical_headers,
        canonical_additional_headers,
        body_digest
    )
    ngx.log(ngx.INFO,"xx:\n" .. xx)

    ngx.log(ngx.INFO,"canonical_request:\n" .. canonical_request)
  return get_sha256_digest(canonical_request)
end

local function get_string_to_sign(timestamp, region, service, host, uri, body_digest)
  return 'OSS4-HMAC-SHA256\n'
      .. get_iso8601_basic(timestamp) .. '\n'
      .. get_cred_scope(timestamp, region, service) .. '\n'
      .. get_hashed_canonical_request(timestamp, host, uri, body_digest)
end




local function get_authorization(keys, timestamp, region, service, host, uri, body_digest)
  local derived_signing_key = get_derived_signing_key(keys, timestamp, region, service)
  local string_to_sign = get_string_to_sign(timestamp, region, service, host, uri, body_digest)

    ngx.log(ngx.INFO, "derived_signing_key:\n" .. str.to_hex(derived_signing_key))
    ngx.log(ngx.INFO, "String to sign:\n" .. string_to_sign)
    local canonical_additional_headers = get_canonical_additional_headers(ngx.req.get_headers(), nil)

    local auth = "OSS4-HMAC-SHA256 "
      .. 'Credential=' .. keys['access_key'] .. '/' .. get_cred_scope(timestamp, region, service)
      --.. ',AdditionalHeaders=' .. canonical_additional_headers
      .. ',Signature=' .. str.to_hex(get_signature(derived_signing_key, string_to_sign))
      ngx.log(ngx.INFO, "auth:\n" .. auth)

  return auth
end


local function oss_auth_v4()
   local method = ngx.req.get_method()
   local content_md5 = ngx.var.http_content_md5 or ''
   local content_type = ngx.var.http_content_type or ''
   local date = ngx.var.http_x_oss_date or ngx.var.http_date or ''
   if date == '' then
      date = ngx.http_time(ngx.time())
      ngx.req.set_header('Date', date)
   end

   ngx.log(ngx.INFO, 'content_md5:'..content_md5)
   ngx.log(ngx.INFO, 'http_content_type:'..content_type)
   -- 打印headers
   ngx.log(ngx.INFO, 'print headers >>>>>>>>>>>')
   for k, v in pairs(ngx.req.get_headers()) do
      ngx.log(ngx.INFO,  k, ':', v)
   end

   ngx.log(ngx.INFO, '<<<<<<<<<<<<<')

   local timestamp = tonumber(ngx.time())
   local datetime_now_iso8601=get_iso8601_basic(timestamp)
   local datetime_now_iso8601_short=get_iso8601_basic_short(timestamp)

   ngx.req.set_header('x-oss-date', datetime_now_iso8601)
   ngx.req.set_header('Date', date)

   ngx.log(ngx.INFO, 'uri:', ngx.var.uri)
   local my_uri = ngx.unescape_uri(ngx.var.uri)
   ngx.log(ngx.INFO, 'my_uri:', my_uri)
   if string_ends(my_uri,'/')
   then
      ngx.req.set_uri('/')
   else
       ngx.req.set_uri("/"..my_uri)
   end

   local body_digest = 'UNSIGNED-PAYLOAD'
   ngx.req.set_header("x-oss-content-sha256", body_digest)
   local region='cn-beijing'
   local host=ngx.var.host
   local service='oss'


--    local resource = get_canon_resource()
--    local canon_headers = get_canon_headers()
   local creds = get_credentials()
   local auth = get_authorization(creds, timestamp, region, service, host, my_uri, body_digest)
--    local sign_result, sign_str = calc_sign(oss_auth_key, method, content_md5,
--    content_type, date, canon_headers, resource)

    -- 设置请求头
    ngx.req.set_header("Authorization", auth)
   if string_ends(my_uri,'/')
   then
       ngx.log(ngx.INFO, 'prefix:', my_uri)
       ngx.exec("/oss",{ prefix=my_uri, delimiter='/'})
   else
       ngx.exec("@oss")
   end
end

-- main
local my_method=ngx.req.get_method()
if my_method == "HEAD" then
    ngx.exit(ngx.OK)
end

local uri = ngx.var.uri
if not string_starts(ngx.var.uri,"share2") then
   uri = "share2"..ngx.var.uri
end

ngx.req.set_uri(uri)

res = oss_auth_v4()
if res then
   ngx.exit(res)
end
