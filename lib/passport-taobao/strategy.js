/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError;

/**
 * `Strategy` constructor.
 *
 * The Renren authentication strategy authenticates requests by delegating to
 * Renren using the OAuth 2.0 protocol.
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
 *   — `userAgent`     All API requests MUST include a valid User Agent string.
 *                     e.g: domain name of your application.
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
  options.authorizationURL = options.authorizationURL || 'https://oauth.taobao.com/authorize';
  options.tokenURL = options.tokenURL || 'https://oauth.taobao.com/token';
  options.scopeSeparator = options.scopeSeparator || ',';
  options.customHeaders = options.customHeaders || {};

  if (!options.customHeaders['User-Agent']) {
    options.customHeaders['User-Agent'] = options.userAgent || 'passport-taobao';
  }

  OAuth2Strategy.call(this, options, verify);
  this.name = 'taobao';
  this._userProfileURL = options.userProfileURL || 'https://eco.taobao.com/router/rest';
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
  var url = 'https://eco.taobao.com/router/rest?format=json&v=2.0&fields=uid,nick,avatar&method=taobao.user.buyer.get';
  url = url +'&app_key='+oauth2._clientId;
  url = url +'&timestamp='+Date.parse(new Date());
  url = url +'&access_token='+accessToken;
  oauth2.get(url, accessToken, function (err, result, res) {
    if (err) {
      return done(new InternalOAuthError('failed to fetch user profile', err));
    }
    try {
      if(result) {
        var json = JSON.parse(result);
        if(json.error_response)
          return done(new InternalOAuthError(json.error_response.msg, new Error(json.error_response.msg)));
        else {
          var json = JSON.parse(result);
          var profile = {provider: 'taobao'};
          profile.id = json.uid;
          profile.nickname = json.nick;
          profile.avatar = json.avatar;
          profile._raw = result;
          profile._json = json;
          done(null, profile);
        }
      }
    } catch (e) {
      done(e);
    }
  });
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
