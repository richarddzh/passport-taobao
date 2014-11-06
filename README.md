# Passport-taobao

copied from [Passport-github](https://github.com/jaredhanson/passport-github) by [Jared Hanson](http://github.com/jaredhanson)

[Passport](http://passportjs.org/) strategy for authenticating with [taobao](http://open.taobao.com/)
using the OAuth 2.0 API.

This module lets you authenticate using Taobao in your Node.js applications.
By plugging into Passport, Taobao authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Installation

    $ npm install passport-taobao

## Usage

#### Configure Strategy

The Taobao authentication strategy authenticates users using a Taobao account
and OAuth 2.0 tokens.  The strategy requires a `verify` callback, which accepts
these credentials and calls `done` providing a user, as well as `options`
specifying a client ID, client secret, and callback URL.

    passport.use(new TaobaoStrategy({
        clientID: client_id,
        clientSecret: client_secret,
        callbackURL: "http://127.0.0.1:3000/auth/taobao/callback"
      },
      function(accessToken, refreshToken, profile, done) {
        User.findOrCreate({ taobaoId: profile.id }, function (err, user) {
          return done(err, user);
        });
      }
    ));

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'taobao'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get('/auth/taobao',
      passport.authenticate('taobao'),
      function(req, res){
        // The request will be redirected to taobao for authentication, so this
        // function will not be called.
      });

    app.get('/auth/taobao/callback',
      passport.authenticate('taobao', { failureRedirect: '/login' }),
      function(req, res) {
        // Successful authentication, redirect home.
        res.redirect('/');
      });

## License

(The MIT License)
