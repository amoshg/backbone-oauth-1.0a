backbone-oauth-1.0a
===================

OAuth 1.0a Plugin for Backbone.js

This library is designed to implement a pure javascript oauth 1.0a. There are a certain security concerns related to the storage of consumer token/secret that you should know about before using this method. This is a good article on one possible way to get around it: http://derek.io/blog/2010/how-to-secure-oauth-in-javascript/. In some cases this security issue is not a real concern and it differs case by case.

-----------------------------------------------------------------------------------------------------------

Before getting started make sure you know the oauth 1.0a flow --> (http://oauth.net/core/diagram.png)

This library uses Ajax request to communicate with the server and do that handshake. It assumes that both parties are on the same domain (in most cases this is not true). Eitehr CORS or JSONP method could be used to get around the same-origin-policy.

A simple example is as follows: 

    
        //create a new oauth instance
         var oauth = $.oauth = new app.OAuth({
            consumerKey : "xxxxxxxxxxxxxxxxx",
            consumerSecret: "xxxxxxxxxxxxxxxxxxx",
            requestURL : "http://yourdomain.com/services/oauth/request_token",
            authURL : "http://yourdomain.com/services/oauth/user_authorization",
            accessURL : "http://yourdomain.com/services/oauth/access_token"
        });
        //get the access token if one exists
        var atoken = window.localstorage.getItem("accessToken");
        //do we have an access token and is the access token valid  && oauth.validateToken(atoken)
       if(!(atoken)){
           //if tokensecret exists then we have already verified the token
           if(location.href.indexOf("oauth_verifier")>-1){
               atoken = oauth.getAccessToken( window.localstorage.getItem("tokenSecret"));
           } else{
               //looks like we need to go grab an acces token
               atoken = oauth.getRequestToken();
           }
          //store it in localstorage
           window.localstorage..setItem("accessToken", atoken);
        }
        
After the access token is retrieved then we can use it to make oauth requests using a method like below 

    //an example of how to request a protected end point after accesstoken is retrieved 
    getProtectedEndpoint : function(url, tokenSecret, accessToken){
      this.tokenSecret = tokenSecret;
      this.token = accessToken
      this.verifier = "";
      var hg = this.headerGenerator();
      var that = this;
      $.ajax({
        type: "GET",
        data : {oauth_callback:"oob"},
        success: function(res) { console.log(res); },                                                                                                                                                                                       
        error: function(res) {},
        beforeSend: function(xhr){
          this.url = this.url + "?" + hg("get",this.url,"").replace(/"/g,"").replace(/, /g,"&");
        },
        url: url,
      });
    } 
        
