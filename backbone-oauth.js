/* 
 * Backbone oAuth 1.0a Implementation
 * Version 1.0; Author Amin Moshgabadi (http://foresee.com) © 2013
 * This software may be freely distributed under the MIT license.
 */

(function(window) {
  "use strict";

  // Quick refrence backbone
  var Backbone = window.Backbone;

  var isBusy = false;

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
    //parts taken from 
    qsString : function(obj) {
      var that = this;
      var str = "";
      //sort the passed object 
      var sorted = this.sortObject(obj);

      var form = "";
      //form encode the sorted object 
      for (var p = 0; p < sorted.length; ++p) {
          var value = sorted[p][1];
          if (value == null) value = "";
          if (form != "") form += '&';
          form += this.percentEncode(sorted[p][0])
            +'='+ this.percentEncode(value);
      }

        return form;

    },

    sortObject : function(obj){
      var list = [];
        for (var p in obj) {
            list.push([p, obj[p]]);
        }
        //sort the list
          var sortable = [];
          for (var p = 0; p < list.length; ++p) {
              var nvp = list[p];
            
                  sortable.push([ this.percentEncode(nvp[0])
                                + " " // because it comes before any character that can appear in a percentEncoded string.
                                + this.percentEncode(nvp[1])
                                , nvp]);
              
          }
          sortable.sort(function(a,b) {
                            if (a[0] < b[0]) return  -1;
                            if (a[0] > b[0]) return 1;
                            return 0;
                        });
          var sorted = [];
          for (var s = 0; s < sortable.length; ++s) {
              sorted.push(sortable[s][1]);
          }
      return sorted;
  },

    //converts the string to an object
    stringQs : function(s) {
      var query = {};

      s.replace(/\b([^&=]*)=([^&=]*)\b/g, function (m, a, d) {
        if (typeof query[a] != 'undefined') {
          query[a] += ',' + d;
        } else {
          query[a] = d;
        }
      });

     return query;
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
    authHeader : function(obj, urlParam) {
      var str = "";

      if(urlParam){
        str = "";
      }else{
        str = "OAuth ";
      }

     var that = this;
     var sorted = this.sortObject(obj);
     for(var i=0;i<sorted.length;i++){
      str += that.percentEncode(sorted[i][0]) + '="' + that.percentEncode(sorted[i][1]) + '", '
     }

     return str.slice(0,str.length-2);

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

      return function(method, uri, extra_params, special) {
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
          oauth_params.oauth_signature = that.signature(consumer_secret, token_secret, base_str);
          var res = {};
          var auth_params =  (extra_params?_.extend({}, extra_params, oauth_params):oauth_params);

          return auth_params;
      };
    },

    //helper function to convert the response url parametrs to a JSON object
    urlParamsToObj : function(str){
      return JSON.parse('{"' + decodeURI(str).replace(/"/g, '\\"').replace(/&/g, '","').replace(/=/g,'":"') + '"}');
    },
    //gets the temp token and secret
    getRequestToken : function(){
      if(!isBusy){
        isBusy = true;
        var hg =this.headerGenerator();
        var that = this;
        $.ajax({
          type: "GET",
          data : {},
           xhrFields: {
            withCredentials: true
          },
           //crossDomain: false,
          success: function(res) { 
            isBusy = false;
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
          error: function(res) {
            isBusy = false;
           // window.location.replace($.serverRoot + "/index.html");
           },
          beforeSend: function(xhr){
            if($.browser.msie){
              this.url = this.url + "?" + that.authHeader(hg("get",this.url,"oauth_callback=" + location.href),true).replace(/"/g,"").replace(/, /g,"&");
            }else{
              xhr.setRequestHeader("Authorization",that.authHeader(hg("get",this.url,"oauth_callback=" + location.href)));
            }
          },
          url: this.requestURL,
        });
    }
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
        data : {oauth_token: this.token, verifier: this.verifier},
         xhrFields: {
       withCredentials: true
         },
      //  crossDomain: false,
        success: function(res) {

         //   that.tokenSecret = that.urlParamsToObj(res).oauth_token_secret;
            if(Backbone.store){
              //store our token info before leaving 
             Backbone.store.set("tokenSecret",that.urlParamsToObj(res).oauth_token_secret);
            }

         clbk(that.urlParamsToObj(res).oauth_token) },                                                                                                                                                                                       
        error: function(res) { 
          throw("error validating access token");
        },
        beforeSend: function(xhr){
           if($.browser.msie){
              this.url = this.url + "&" + that.authHeader(hg("get",this.url,""),true).replace(/"/g,"").replace(/, /g,"&");
            }else{
              xhr.setRequestHeader("Authorization",that.authHeader(hg("get",this.url,"")));
            }
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
        data : {},
         xhrFields: {
       withCredentials: true
      },
    //    crossDomain: false,
        success: function(res) { 
          if(typeof res === "string"){
            that.token = "";
            that.tokenSecret = "";
            that.getRequestToken();
          }else{
          options.success(res) }
        },                                                                                                                                                                                       
        error: function(res) { 
          throw("error grabbing resource");
        },
        beforeSend: function(xhr){
              if($.browser.msie){
              this.url = this.url + "?" + that.authHeader(hg("get",this.url,""),true).replace(/"/g,"").replace(/, /g,"&");
            }else{
              xhr.setRequestHeader("Authorization",that.authHeader(hg("get",this.url,"")));
            }
        },
        url: url,
      });
    }

  }

})(this);
