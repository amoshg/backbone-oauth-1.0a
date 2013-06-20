/* 
 * Backbone oAuth 1.0a Implementation
 */

(function(window) {
  "use strict";

  // Alias backbone, underscore and jQuery.
  var Backbone = window.Backbone,
      _        = window._,
      $        = window.$;

  // Extend Backbone with OAuth functionality.
  Backbone.OAuth || (Backbone.OAuth = {});

  // The base OAuth class.
  Backbone.OAuth = function(options) {
      // Override any default option with the options passed to the constructor.
    _.extend(this, options);
    
  };
 // Inject methods and properties.
  _.extend(Backbone.OAuth.prototype, {
    //the oAuth Version
    version : "1.0a",

    //the signature method
    signature_method : "HMAC-SHA1",

    //The term nonce means ‘number used once’ and is a unique and usually random string that is meant to uniquely identify each signed request
    nonce : function() {
        for (var o = ''; o.length < 6;) {
            o += '0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz'[Math.floor(Math.random() * 61)];
        }
        return o;
    },

    //The name says it all, a time stamp
    timestamp : function() { return ~~((+new Date()) / 1000); },

    //percent encode the given string
    percentEncode: function(s) {
      return encodeURIComponent(s)
          .replace(/\!/g, '%21').replace(/\'/g, '%27')
          .replace(/\*/g, '%2A').replace(/\(/g, '%28').replace(/\)/g, '%29');
    },

    //the base String
    baseString : function(method, url, params) {
      if (params.oauth_signature) delete params.oauth_signature;
      return [
          method,
          percentEncode(url),
          percentEncode(qsString(params))].join('&');
    },

    //query string
    qsString : function(obj) {
      return Object.keys(obj).sort().map(function(key) {
          return ohauth.percentEncode(key) + '=' +
              ohauth.percentEncode(obj[key]);
      }).join('&');
    },

    //the HMAC-SHA1 Signature
    signature : function(oauth_secret, token_secret, baseString) {
      return sha1.b64_hmac(
          percentEncode(oauth_secret) + '&' +
          percentEncode(token_secret),
          baseString);
      }

  });


})(this);
