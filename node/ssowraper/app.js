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