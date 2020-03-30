### ngnix反向代理和认证

#### nginx + lua部署
由于使用中需要别的模块，因此部署也包括第三方模块的安装，可根据需要再添加自己需要的模块和依赖

1. 安装系统依赖

```
$ yum -y install make zlib zlib-devel gcc-c++ libtool openssl openssl-devel
```

2. lua安装

	1) 获取lua并进行编译

	```
	$ git clone https://github.com/openresty/luajit2
	$ make
	$ make install PREFIX=/usr/local/luajit2
	```
	2) 设置环境变量

	```
	$ export LUAJIT_LIB=/usr/local/luajit/lib
	$ export LUAJIT_INC=/usr/local/luajit/include/luajit-2.1
	```
	3) 修改系统配置

	```
	$ echo "/usr/local/luajit2/lib" >> /etc/ld.so.conf
    $ ldconfig
	```

3. 下载ngx_devel_kit, lua-nginx-module和echo-nginx-module并解压

```
$ wget https://github.com/simplresty/ngx_devel_kit/archive/v0.3.1rc1.tar.gz
$ tar -xzvf v0.3.1rc1.tar.gz
$ wget https://github.com/openresty/lua-nginx-module/archive/v0.10.14rc3.tar.gz
$ tar -xzvf v0.10.14rc3.tar.gz
$ wget https://github.com/openresty/echo-nginx-module/archive/v0.61rc1.tar.gz
$ tar -xzvf v0.61rc1.tar.gz
```

4. ngnix下载和安装

	1) nginx下载

	```
	$ http://nginx.org/en/download.html 下载nginx-1.17.9.tar.gz
	$ tar -zxvf nginx-1.17.9.tar.gz
	```
	2) 编译和安装, ```--with-http_auth_request_module```添加认证模块，用来支持ngnix本机认证和第三方认证

	```
	$ ./configure --with-http_auth_request_module --add-module=/data/ngx_devel_kit-0.3.1rc1 --add-module=/data/lua-nginx-module-0.10.14rc3 --add-module=/data/echo-nginx-module-0.61rc1
	$ make -j4 && make install
	```

5. 创建Demo应用服务器和认证服务器

	1) 下载和安装node具体请参照官网 ```https://nodejs.org/en/```

	2) 安装express-generator用它来生产node项目框架

	```
	$ npm install express-generator -g
	```
	3) 创建应用服务器(当然也可以用你已经存在的应用服务器，这里我们后面对接使用的是ambari，hdfsUI和ranger)

	```
	$ express -e --git myweb
	$ cd myweb
	$ npm install
	```

	4) 修改饮用服务器端口为4000

	```
	$ cat bin/www
   var port = normalizePort(process.env.PORT || '4000');
	```

	5) 创建认证服务器

	```
	$ express -e --git mycase
	$ cd note
	$ npm install
	```

	6) 修改饮用服务器端口为3002

	```
	$ cat bin/www
   var port = normalizePort(process.env.PORT || '3002');
	```

	7) 修改应用服务器的app.js（require的module可以通过npm install 自行安装）

	```
	$ cat myweb/app.js
	var createError = require('http-errors');
	var express = require('express');
	var path = require('path');
	var cookieParser = require('cookie-parser');
	var logger = require('morgan');
	var bodyparser = require('body-parser');
	var expresssession = require('express-session');
	var indexRouter = require('./routes/index');
	var usersRouter = require('./routes/users');
	var app = express();
	// view engine setup
	app.set('views', path.join(__dirname, 'views'));
	app.set('view engine', 'ejs');
	app.use(logger('dev'));
	app.use(express.json());
	app.use(express.urlencoded({ extended: false }));
	app.use(cookieParser());
	app.use(express.static(path.join(__dirname, 'public')));
	app.use(bodyparser.json());
	app.use(bodyparser.urlencoded({ extended: false }));
	app.use(expresssession({
	    secret: 'mysecret',
	    resave: true,
	    saveUninitialized: false,
	    cookie: {
	        maxAge: 1000 * 60 * 3
	    }
	}));
	app.get('/', function (req, res) {
	    console.log("/ session.id   =", req.session.id);
	    console.log("/ session.user =", req.session.user);
	    console.log("/ headers.user =", req.headers["user"]);
	    console.log("/ cookies.user =", req.cookies["user"]);

	    user = req.cookies["user"]
	    if (user) {
	        req.session.user= user;
	        res.end('Welcome Page!');
	    } else {
	        console.error("401 Unauthorized");
	        res.end('401 Unauthorized');
	    }
	});
	app.get('/logout', function (req, res) {
	    console.log("/ session.id   =", req.session.id);
	    console.log("/ session.user =", req.session.user);
	    console.log("/ headers.user =", req.headers["user"]);

	    req.session.destroy();
	    res.redirect('http://host.example.com:3000/logout');
	});
	app.use('/', indexRouter);
	app.use('/users', usersRouter);
	// catch 404 and forward to error handler
	app.use(function(req, res, next) {
	  next(createError(404));
	});
	// error handler
	app.use(function(err, req, res, next) {
	  // set locals, only providing error in development
	  res.locals.message = err.message;
	  res.locals.error = req.app.get('env') === 'development' ? err : {};

	  // render the error page
	  res.status(err.status || 500);
	  res.render('error');
	});
	module.exports = app;
    ```

	8) 修改认证服务器app.js（这里给出的是和ambari sso集成用的demo code）

	```
	$ cat mycase/app.js
    var createError = require('http-errors');
    var express = require('express');
    var path = require('path');
    var cookieParser = require('cookie-parser');
    var logger = require('morgan');
    var bodyparser = require('body-parser');
    var expresssession = require('express-session');
    var cookie = require('cookie-parser');
    var crypto = require('crypto');

    var indexRouter = require('./routes/index');
    var usersRouter = require('./routes/users');

    var userTokens = {};
    var userDatabase = { 'admin': 'admin' };

    var app = express();

    // view engine setup
    app.set('views', path.join(__dirname, 'views'));
    app.set('view engine', 'ejs');

    app.use(logger('dev'));
    app.use(express.json());
    app.use(express.urlencoded({ extended: false }));
    app.use(cookieParser());
    app.use(express.static(path.join(__dirname, 'public')));

    app.use(cookie());
    app.use(bodyparser.json());
    app.use(bodyparser.urlencoded({ extended: false }));
    app.use(expresssession({
        secret: 'mysecret',
        resave: true,
        saveUninitialized: false,
        cookie: {
            maxAge: 1000 * 60 * 3
        }
    }));

    app.get('/login', function (req, res) {
        console.log("/login req.session.id = ", req.session.id);
        console.log("/login req.headers    = ", req.headers);
        console.log("/login req.query = ", req.query.port);
        res.sendFile(path.join(__dirname, './public/templates', 'login.html'));
    });

    app.post('/login', function (req, res) {
        var user = req.body.username;
        var pass = req.body.password;
        console.log("/login POST req.session.id=", req.session.id);
        if (userDatabase.hasOwnProperty(user) && userDatabase[user] == pass) {
            // when username/password is valid
            //var token = crypto.createHash('sha256').update(req.session.id).digest("hex")
            var token = crypto.createHash('sha256').update(user).digest("hex")
            req.session.user= user;
            req.session.token= token;

            res.cookie('user', user);
            res.cookie('token', token);
            // hard code to set Basic auth admin
            res.cookie('authorization', 'YWRtaW46YWRtaW4=');
            userTokens[user] = user;
            console.log("/login POST generate token[", token, "] for user [", user, "]");
            // hard code the ngnix proxy ip, it can resolved from cookie 'redirect'
            res.redirect("http://10.1.236.197:"+ req.body.port)
        } else {
            res.redirect('/login');
        }
    });

    app.get('/auth', function (req, res) {
        console.log("/auth session.id    : " + req.session.id);
        console.log("/auth session.user  : " + req.session.user);
        console.log("/auth session.token : " + req.session.token);
        console.log("/auth cookie.user   : " + req.cookies.user);
        console.log("/auth cookie.token  : " + req.cookies.token);

        token = req.cookies.token;
        user  = req.cookies.user;

        //if (userTokens[token] && userTokens[token] == user) {
        // hard code to check if the admin in memory, future can check with
        // sso server
        if(userTokens['admin'] === 'admin'){
            console.log("/auth return success");
            //res.setHeader("X-Forwarded-User", user);
            //res.setHeader("user", user);
            res.end();
        } else {
            console.log("/auth return failure");
            res.status(401);
            res.end();
        }
    });

    app.get('/logout', function (req, res) {
        console.log("/logout req.session.id : " + req.session.id);
        req.session.destroy();
        res.clearCookie("user");
        res.clearCookie("token");
        res.redirect('/login');
    });

    app.use('/', indexRouter);
    app.use('/users', usersRouter);

    // catch 404 and forward to error handler
    app.use(function(req, res, next) {
      next(createError(404));
    });

    // error handler
    app.use(function(err, req, res, next) {
      // set locals, only providing error in development
      res.locals.message = err.message;
      res.locals.error = req.app.get('env') === 'development' ? err : {};

      // render the error page
      res.status(err.status || 500);
      res.render('error');
    });

    module.exports = app;
	```

	9) 为认证服务器添加一个登录页面

	```
	<!DOCTYPE html>

	<html>
	<head>
	<meta charset="ISO-8859-1">
	<title>Insert title here</title>
	<style type="text/css">
	 body{
	  margin: 100px 0px;
	  padding:0px;
	  text-align:center;
	  align:center;
	  }

	 input[type=text], input[type=password]{
	    width:20%;
	    padding:7px 10px;
	    margin: 8px 0;
	    display:inline-block;
	    border: 1px solid #ccc;
	    box-sizing: border-box;
	  }

	 button{
	     background-color:#4CAF50;
	     width: 10%;
	     padding: 9px 5px;
	     margin:5px 0;
	     cursor:pointer;
	     border:none;
	     color:#ffffff;
	  }

	 button:hover{
	   opacity:0.8;
	 }

	#un,#ps{
	 font-family:'Lato', sans-serif;
	 color: gray;
	}
	</style>
	</head>

	<body>
	  <div id="container">
	    <form action="/login" method="post">
	      <h2>Login Form</h2>

	      <label for="username" id="un">Username:</label>
	      <input type="text" name="username" id="username"><br/><br/>

	      <label for="password" id="ps">Password:</label>
	      <input type="password" name="password" id="password"><br/><br/>

	      <button type="submit" value="Login"  id="submit">Login</button>
	      <input type="hidden" name="port" id="port"></input>
	 </form>
	  </div>
	</body>

	<script type="text/javascript">
	function getPar(par){

	    var local_url = document.location.href;

	    var get = local_url.indexOf(par +"=");
	    if(get == -1){
	        return false;
	    }

	    var get_par = local_url.slice(par.length + get + 1);

	    var nextPar = get_par.indexOf("&");
	    if(nextPar != -1){
	        get_par = get_par.slice(0, nextPar);
	    }
	    return get_par;
	}
	document.getElementById("port").value=getPar('port');
	</script>

	```

6. 	ngnix配置文件

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

    server {
        listen       6080;
        server_name  localhost;

        location / {
            auth_request /auth;
            error_page 401 = @error401;

            default_type 'text/plain';
            set $aa "";
            rewrite_by_lua '
                t = {}
                if ngx.var.http_cookie then
                s = ngx.var.http_cookie
                  for k, v in string.gmatch(s, "(%w+)=([%w%/%.%%=_-]+)") do
                      t[k] = v
                  end
                end
                if (t["authorization"] ~= nil) then
                  ss = string.gsub(t["authorization"], "%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end)
                  ngx.var.aa="Basic "..ss
                end
            ';

            proxy_set_header Authorization $aa;
            proxy_pass http://10.1.236.58:6080;
        }


        location /auth {
            internal;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            proxy_pass http://10.1.236.197:3002/auth;
        }

        location @error401 {
            add_header Set-Cookie "redirect=$scheme://$http_host$request_uri;Path=/;Max-Age=3000";
            return 302 http://10.1.236.197:3002/login?port=$server_port;
        }
    }

    server {
        listen       9009;
        server_name  localhost;

        location /hello {
            default_type 'text/plain';
            content_by_lua 'ngx.say("hello, lua")';
        }
    }

    server {
        listen       50070;
        server_name  localhost;

        location / {
            auth_request /auth;
            error_page 401 = @error401;

            proxy_pass http://10.1.236.145:50070;
        }
        location /auth {
            internal;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";

            proxy_pass http://10.1.236.197:3002/auth;
        }

        location @error401 {

            add_header Set-Cookie "redirect=$scheme://$http_host$request_uri;Path=/;Max-Age=3000";
            return 302 http://10.1.236.197:3002/login?port=$server_port;
        }
        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }
    }

    server {
        listen       9001;
        server_name  localhost;

        #auth_basic "User Authentication";
        #auth_basic_user_file /usr/local/nginx/conf/pass.db;
        #access_log  logs/host.access.log  main;

        location / {
            auth_request /auth;
            error_page 401 = @error401;

            default_type 'text/plain';
            set $aa "";
            rewrite_by_lua '
                t = {}
                if ngx.var.http_cookie then
                s = ngx.var.http_cookie
                  for k, v in string.gmatch(s, "(%w+)=([%w%/%.%%=_-]+)") do
                      t[k] = v
                  end
                end
                if (t["authorization"] ~= nil) then
                  ss = string.gsub(t["authorization"], "%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end)
                  ngx.var.aa="Basic "..ss
                end
            ';

            #echo "res = $aa";
            proxy_set_header Authorization $aa;
            proxy_pass http://10.1.236.145:8080;
        }


        location /auth {
            internal;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            proxy_pass http://10.1.236.197:3002/auth;
        }

        location @error401 {
            add_header Set-Cookie "redirect=$scheme://$http_host$request_uri;Path=/;Max-Age=3000";
            return 302 http://10.1.236.197:3002/login?port=$server_port;
        }

        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }
    }

}



参考：https://www.jianshu.com/p/59c1c4f3dfab
```

7. nginx 如何重定向https

```
$ 编译的时候 --with-http_ssl_module
$ nginx.conf 添加 return 301 https://localhost:8443/gateway/ocdp/yarn;
```
	
	
