/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError;
var crypto = require('crypto');

/**
 * `Strategy` constructor.
 *
 * The Taobao authentication strategy authenticates requests by delegating to
 * Taobao using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Taobao application's Client ID
 *   - `clientSecret`  your Taobao application's Client Secret
 *   - `callbackURL`   URL to which Taobao will redirect the user after granting authorization
 *   - `scope`         array of permission scopes to request.  valid scopes include:
 *                     'user', 'public_repo', 'repo', 'gist', or none.
 *   — `sandbox`       set true to use taobao sandbox environment..
 *
 * Examples:
 *
 *     passport.use(new TaobaoStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/taobao/callback',
 *         userAgent: 'myapp.com'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  if (options.sandbox) {
    options.authorizationURL = options.authorizationURL || 'https://oauth.tbsandbox.com/authorize';
    options.tokenURL = options.tokenURL || 'https://oauth.tbsandbox.com/token';
  } else {
    options.authorizationURL = options.authorizationURL || 'https://oauth.taobao.com/authorize';
    options.tokenURL = options.tokenURL || 'https://oauth.taobao.com/token';
  }
  options.scopeSeparator = options.scopeSeparator || ',';
  options.customHeaders = options.customHeaders || {};

  OAuth2Strategy.call(this, options, verify);
  this.name = 'taobao';
  if (options.sandbox) {
    var oauth2 = this._oauth2;
    oauth2._chooseHttpLibrary = function(parsedUrl) {
      var isHttps = (parsedUrl.protocol.indexOf('https') === 0);
      var httpLib =  Object.getPrototypeOf(oauth2)._chooseHttpLibrary.call(oauth2, parsedUrl);
      if (isHttps) httpLib._isHttps = isHttps;
      return httpLib;
    };
    oauth2._executeRequest = function(http_library, options, post_body, callback) {
      if (http_library._isHttps) {
        options.rejectUnauthorized = false;
        options.agent = new http_library.Agent(options);
      }
      Object.getPrototypeOf(oauth2)._executeRequest.call(oauth2, http_library, options, post_body, callback);
    };
    this._userProfileURL = options.userProfileURL || 'http://gw.api.tbsandbox.com/router/rest';
  } else {
    this._userProfileURL = options.userProfileURL || 'http://gw.api.taobao.com/router/rest';
  }
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile from GitHub.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `taobao`
 *   - `id`              the user's Taobao ID
 *   - `nickname`             the user's name
 *
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function (accessToken, done) {
  var oauth2 = this._oauth2;
  var url = this._userProfileURL;

  // sign the query
  var query = {
    'format': 'json',
    'v': '2.0',
    'fields': 'nick,sex,uid,user_id,birthday,type,email,avatar',
    'method': 'taobao.user.seller.get',
    'app_key': oauth2._clientId,
    'timestamp': Date.parse(new Date()),
    'sign_method': 'md5',
    'session': accessToken
  };
  var md5 = crypto.createHash("md5");
  md5.update(oauth2._clientSecret);
  Object.keys(query).sort().forEach(function(key) {
    md5.update(key + query[key]);
  });
  md5.update(oauth2._clientSecret);
  query.sign = md5.digest("hex").toUpperCase();
  url += '?' + Object.keys(query).map(function(key) {
    return key + '=' + query[key];
  }).join('&');

  if(!accessToken) {
    return done( new Error('accessToken is empty'));
  }
  // provide empty accessToken to prevent oauth2 append accessToken to URL
  oauth2.get(url, /*accessToken=*/'', function (err, result, res) {
    if (err) {
      return done(new InternalOAuthError('failed to fetch user profile', err));
    }
    try {
      if(result) {
        console.log(result);
        var json = JSON.parse(result);
        if(json.error_response)
          return done(new InternalOAuthError(json.error_response.code + '-' + json.error_response.msg, new Error(json.error_response.msg)));
        else {
          var json = JSON.parse(result);
          var json2 = json.user_seller_get_response.user;
          var profile = {provider: 'taobao'};
          profile.id = json2.uid || json2.user_id;
          profile.nickname = json2.nick;
          profile.avatar = json2.avatar;
          profile._raw = result;
          profile._json = json;
          done(null, profile);
        }
      }
    } catch (e) {
      done('ERROR:'+e+result);
    }
  });
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
