# AuthDL
一个用 Go 语言编写的轻量级单二进制下载网关。

具有验证码验证、七牛 CDN 时间戳防盗链功能，以及零依赖部署。

# 快速开始

配置文件 /app/config.json

``` json
{
  "baseURL": "http://a.com/", // 开启时间戳防盗链的 CDN
  "encryptKey": "xxxx", // KEY
  "deadline": 60, // 时效性 60s
  "enableCaptcha": true // 开启验证码验证
}
```

``` bash
docker run --rm --name authdl \
  -p 8080:8080 \
  -v ./authdl.json:/app/config.json \
  qvgz/authdl

# 查看版本
docker exec -it authdl ./authdl vsrsion
# 检查配置
docker exec -it authdl ./authdl check
# 优雅重启
docker exec -it authdl ./authdl reload
```

# 注意事项

base64Captcha.DefaultMemStore 将验证码存储在内存中。

/api/captcha 接口无限制，攻击者高频请求，内存会被无限撑大导致 OOM (Out of Memory) 崩溃。

务必前置代理程序配置限流措施。

``` conf
# nginx 示范
# 每个 IP 每秒最多请求 5 次，并允许最多 10 个请求的瞬间突发排队，超出部分拒绝。

limit_req_zone $binary_remote_addr zone=one:10m rate=5r/s;
location /api/captcha {
    limit_req zone=one burst=10 nodelay;
    proxy_pass http://127.0.0.1:8080;
}
```
