### ngnix ssl 配置并代理到https


#### nginx 编译需要制定ssl module
```
$ ./configure --with-debug --with-http_ssl_module
```


#### 使用openssl生成证书

##### 创建根证书CA

1. 生成CA私钥
```
openssl genrsa -out local.key 2048
```

2. 生成CA证书请求
```
openssl req -new -key local.key -out local.csr
```

3. 生成CA根证书
```
openssl x509 -req -in local.csr -extensions v3_ca -signkey local.key -out local.crt
```

##### 根据CA证书创建Server端证书

1. 生成Server私钥 
```
openssl genrsa -out my_server.key 2048 
```

2. 生成Server证书请求
```
openssl req -new -key my_server.key -out my_server.csr
```

3. 生成Server证书
```
openssl x509 -days 365 -req -in my_server.csr -extensions v3_req -CAkey local.key -CA local.crt -CAcreateserial -out my_server.crt
```

#### 配置nginx支持SSL
```

user  root;
worker_processes  1;

#error_log  logs/error.log;
#error_log  logs/error.log  notice;
#error_log  logs/error.log  info;

#pid        logs/nginx.pid;


events {
    worker_connections  1024;
}


http {
    include       mime.types;
    default_type  application/octet-stream;

    #log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
    #                  '$status $body_bytes_sent "$http_referer" '
    #                  '"$http_user_agent" "$http_x_forwarded_for"';

    #access_log  logs/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;

    #gzip  on;

    #upstream yarn.local {
    #    server 10.1.236.145:8443/gateway/ocdp/yarn;
    #}

    server {
        listen       443 ssl;
        server_name  knox145.com;
 
        ssl_certificate      /usr/local/nginx/ssl/local.crt;
        ssl_certificate_key  /usr/local/nginx/ssl/local.key;
        location / {
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forward-For $remote_addr;
            proxy_pass https://10.1.236.145:8443;
        }
    }
}

#跳转必须添加，不然会重定向导致css和js不能加载
#proxy_set_header Host $host;
#proxy_set_header X-Real-IP $remote_addr;
#proxy_set_header X-Forward-For $remote_addr;
```