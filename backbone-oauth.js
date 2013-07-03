/* 
 * Backbone oAuth 1.0a Implementation
 * Version 1.0; Author Amin Moshgabadi (http://foresee.com) © 2013
 * This software may be freely distributed under the MIT license.
 */

(function(window) {
  "use strict";

  // Quick refrence backbone
  var Backbone = window.Backbone;

  // Extend Backbone with OAuth functionality.
  Backbone.OAuth || (Backbone.OAuth = {});

  // The base OAuth class.
  Backbone.OAuth = function(opts) {
    this.consumer_key = opts.consumerKey;
    this.consumer_secret = opts.consumerSecret;
    this.requestURL = opts.requestURL;
    this.authURL = opts.authURL;
    this.accessURL = opts.accessURL; 
    this.token = "";
    this.tokenSecret = opts.tokenSecret || "";
    this.verifier = "";
  };

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
      var consumer_key = options.consumer_key || this.consumer_key || '',
          consumer_secret = options.consumer_secret || this.consumer_secret || '',
          signature_method = options.signature_method || 'HMAC-SHA1',
          version = options.version || '1.0',
          token = this.token || options.token || '',
          token_secret = this.tokenSecret || options.token_secret || '',
          verifier= this.verifier || options.verifier || '';  

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
    },
    //gets the temp token and secret
    getRequestToken : function(){
      var hg =this.headerGenerator();
      var that = this;
      $.ajax({
        type: "GET",
        async: false,
        data : {oauth_callback:location.href},
         xhrFields: {
          withCredentials: true
        },
        success: function(res) { 
          var resObj = that.urlParamsToObj(res);
          that.token = resObj.oauth_token; 
          that.tokenSecret = resObj.oauth_token_secret;
          if(Backbone.store){
            //store our token info before leaving 
            Backbone.store.set("tokenSecret",that.tokenSecret);
          }
          
          //now redirect to service to authorize consumer 
          window.location.replace(that.authURL + "?oauth_token=" + resObj.oauth_token);
        },                                                                                                                                                                                       
        error: function(res) { },
        beforeSend: function(xhr){
          this.url = this.url + "&" + hg("get",this.url,"").replace(/"/g,"").replace(/, /g,"&");
        },
        url: this.requestURL,
      });
    },

    constructCallbackURL: function(params, baseurl){
      var str = "";
       for (var key in params) {
        if (str != "") {
          str += "&";
         }
        str += key + "=" + params[key];
       }
      return baseurl + "?" + str;
    },
    //gets the access token given the tokensecret, this method should be called after the user has authenticated the consumer and a verifier has been supplied by the server
    getAccessToken : function(tokenSecret, clbk){
      var atoken = "";
      if(tokenSecret){
        this.tokenSecret = tokenSecret;
      }
      //the url params
      var params = this.urlParamsToObj(window.location.search.replace(/\?/g,""));
      //get the verifier from the url
      this.verifier = params.oauth_verifier;
      this.token = params.oauth_token;
      var hg = this.headerGenerator();
      var that = this;
      $.ajax({
        type: "GET",
        async: false,
        data : {oauth_token: this.token, verifier: this.verifier},
         xhrFields: {
       withCredentials: true
         },
        success: function(res) { clbk(that.urlParamsToObj(res).oauth_token) },                                                                                                                                                                                       
        error: function(res) { 
          throw("error validating access token") 
        },
        beforeSend: function(xhr){
          this.url = this.url + "&" + hg("get",this.url,"").replace(/"/g,"").replace(/, /g,"&");
        },
        url: this.accessURL,
      });

      return atoken;
    }
    
    //an example of how to request a protected end point after accesstoken is retrieved 
    ,apiRequest : function(url, tokenSecret, accessToken, options){
      this.tokenSecret = tokenSecret;
      this.token = accessToken
      this.verifier = "";
      var hg = this.headerGenerator();
      var that = this;
      $.ajax({
        type: "GET",
        data : {oauth_callback:"oob"},
         xhrFields: {
       withCredentials: true
    },
        success: function(res) { 
          if(typeof res === "string"){
            that.token = "";
            that.tokenSecret = "";
            that.getRequestToken();
          }else{
          options.success(res) }
        },                                                                                                                                                                                       
        error: function(res) { 
          options.error(error) },
        beforeSend: function(xhr){
          this.url = this.url + "?" + hg("get",this.url,"").replace(/"/g,"").replace(/, /g,"&");
        },
        url: url,
      });
    }

  },

  //extend backbone sync to use our methods
  Backbone.sync = function(method, model, options) {
    switch (method) { 
      case 'create':
        debugger;
      break;

      case 'update':
        debugger;
      break;

      case 'delete':
        debugger;
      break;

      case 'read':
       $.oauth.apiRequest($.serverRoot + this.url, Backbone.store.get("tokenSecret"), Backbone.store.get("accessToken"), options);
      break;
    }
  };


})(this);
