/* 
 * Backbone oAuth 1.0a Implementation
 */

(function(window) {
  "use strict";

  // Quick refrence backbone
  var Backbone = window.Backbone;

  // Extend Backbone with OAuth functionality.
  Backbone.OAuth || (Backbone.OAuth = {});

  // The base OAuth class.
  Backbone.OAuth = function(opts) {};

  //set the object prototype
  Backbone.OAuth.prototype = {
    //The term nonce means ‘number used once’ and is a unique and usually random string that is meant to uniquely identify each signed request
    nonce : function() {
        for (var o = ''; o.length < 32;) {
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
    //you guessed it! percent decode a string
    percentDecode: function(s) {
        if (s != null) {
            // Handle application/x-www-form-urlencoded, which is defined by
            // http://www.w3.org/TR/html4/interact/forms.html#h-17.13.4.1
            s = s.replace(/\+/g, " ");
        }
        return decodeURIComponent(s);
    },
    //the base String (used to create the signature)
    baseString : function(method, url, params) {
      if (params.oauth_signature) delete params.oauth_signature;
      return [
          method,
          this.percentEncode(url),
          this.percentEncode(this.qsString(params))].join('&');
    },

    //converts the given object to a string
    qsString : function(obj) {
      var that = this;
      var str = Object.keys(obj).sort().map(function(key) {
          return that.percentEncode(key) + '=' +
              that.percentEncode(obj[key]);
      }).join('&');

      return str;
    },

    //converts the string to an object
    stringQs : function(str) {
      return str.split('&').reduce(function(obj, pair){
          var parts = pair.split('=');
          obj[decodeURIComponent(parts[0])] = (null === parts[1]) ?
              '' : decodeURIComponent(parts[1]);
          return obj;
      }, {});
    },

    //the HMAC-SHA1 Signature
    //the shaq.b64_hmac is defined in http://pajhome.org.uk/crypt/md5/sha1.js
    signature : function(oauth_secret, token_secret, baseString) {
      return b64_hmac_sha1(
          this.percentEncode(oauth_secret) + '&' +
          this.percentEncode(token_secret),
          baseString);
      },
    //the auth header
    authHeader : function(obj) {
      return Object.keys(obj).sort().map(function(key) {
          return encodeURIComponent(key) + '="' + encodeURIComponent(obj[key]) + '"';
      }).join(', ');
    },
    //this is where the magic happens, this method does the actual header generation for our requests 
    headerGenerator : function(options) {
      options = options || {};
      var consumer_key = options.consumer_key || '',
          consumer_secret = options.consumer_secret || '',
          signature_method = options.signature_method || '',
          version = options.version || '1.0',
          token = options.token || '',
          token_secret = options.token_secret || '',
          verifier= options.verifier || '';  

      var that = this;

      return function(method, uri, extra_params) {
          method = method.toUpperCase();
          if (typeof extra_params === 'string' && extra_params.length > 0) {
              extra_params = that.stringQs(extra_params);
          }

          var uri_parts = uri.split('?', 2),
          base_uri = uri_parts[0];

          var query_params = uri_parts.length === 2 ?
              that.stringQs(uri_parts[1]) : {};

          var oauth_params = {
              oauth_consumer_key: consumer_key,
              oauth_nonce: that.nonce(),
              oauth_signature_method: signature_method,
              oauth_timestamp: that.timestamp()
            };

              if (token) oauth_params.oauth_token = token;
              if(verifier) oauth_params.oauth_verifier = verifier;

              oauth_params.oauth_version  = version;


          var all_params = _.extend({}, oauth_params, query_params, extra_params),
              base_str = that.baseString(method, base_uri, all_params);

              if(token_secret) token_secret = that.percentDecode(token_secret);

          oauth_params.oauth_signature = that.signature(consumer_secret, token_secret, base_str) + "=";

          return that.authHeader(oauth_params);
      };
    }, 

    //helper function to convert the response url parametrs to a JSON object
    urlParamsToObj : function(str){
      return JSON.parse('{"' + decodeURI(str).replace(/"/g, '\\"').replace(/&/g, '","').replace(/=/g,'":"') + '"}');
    }

  };


})(this);
