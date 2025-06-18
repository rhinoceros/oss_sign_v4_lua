
# [参考了](https://github.com/RichieSams/lua-resty-aws-signature/blob/main/lib/resty/aws-signature.lua)

Dockerfile 例子
```
FROM openresty:1.27.1.2-alpine-fat
ENV TZ "Asia/Shanghai"
RUN opm get openresty/lua-resty-string openresty/lua-resty-string jkeys089/lua-resty-hmac
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY oss_auth_v4.lua /usr/local/openresty/nginx/conf/oss_auth.lua


```

nginx.conf 例子
```

env OSS_AUTH_ID;
env OSS_AUTH_KEY;
env OSS_BUCKET;

http {
  server {
        lua_code_cache  on;
        location /oss {
            rewrite /oss / break;
            proxy_pass http://$oss_bucket.oss-cn-beijing-internal.aliyuncs.com;
        }

        location / {
            set_by_lua $oss_bucket 'return os.getenv("OSS_BUCKET")';
            rewrite_by_lua_file "/usr/local/openresty/nginx/conf/oss_auth.lua";
        }
        # internal redirect
        location @oss {
            proxy_pass http://$oss_bucket.oss-cn-beijing-internal.aliyuncs.com;
        }
  }
}

```
