backbone-oauth-1.0a
===================

OAuth 1.0a Plugin for Backbone.js

This library s designed to implement a prue javascript oauth 1.0a. There are a certain security concerns related to the storage of consumer token/secret that you should know about before using this method. This is a good article on one possible way to get around it: http://derek.io/blog/2010/how-to-secure-oauth-in-javascript/. In some cases this security issue is not a real concern and it differs case by case.

-----------------------------------------------------------------------------------------------------------

Before getting started make sure you know the oauth 1.0a flow --> (http://s3.pixane.com/Oauth_diagram.png)

This library uses Ajax request to communicate with the server and do that handshake. It assumes that both parties are on teh same domain (in most cases this is not true). Eitehr CORS or JSONP method could be used to get around the same-origin-policy.

A simple example is as follows: 

    
