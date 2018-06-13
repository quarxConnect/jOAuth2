(function () {
  // {{{ addurlp
  /**
   * Append a set of parameters to a given url
   * 
   * @param string url
   * @param object params
   * 
   * @access private
   * @return string
   **/
  var addurlp = function (url, params) {
    // Prepare the URL
    if (url.indexOf ('?') >= 0)
      url += '&';
    else
      url += '?';
    
    // Append parameters
    for (var p in params)
      if (params [p] != null)
        url += escape (p) + '=' + escape (params [p]) + '&';
    
    // Return the result
    return url.substring (0, url.length - 1);
  }
  // }}}
  
  // {{{ jOAuth2
  /**
   * Create a new jOAuth2 Authorization-Module
   * 
   * @param object options for the module
   * 
   * @access public
   * @return object
   **/
  self.jOAuth2 = function (options) {
    // Initialize all properties
    this.options = {
      authorization_endpoint : null,
      introspection_endpoint : null,
      introspection_method : 'rfc',
      token_endpoint : null,
      client_id : null,
      redirect_uri : null,
      scopes : null,
      storage : window.sessionStorage,
      storage_id : 'default',
      expires_default : 3600000,
      
      onbeforeauthorize : null,
      onauthorize : null,
      onexpiration_warning : null,
      onexpiration : null,
      onerror : null
    };
    
    // Merge external options
    for (var p in this.options)
      if (typeof options [p] != 'undefined')
        this.options [p] = options [p];
    
    return this;
  };
  // }}}
  
  // {{{ getToken
  /**
   * Retrive the currently granted token
   * 
   * @access public
   * @return object
   **/
  self.jOAuth2.prototype.getToken = function () {
    if (!this.token && (this.token = this.options.storage.getItem ('jOAuth2-Token-' + this.options.storage_id)))
      this.token = JSON.parse (this.token);
    
    return this.token;
  };
  // }}}
  
  // {{{ authorize
  /**
   * Make sure that we have an authorization by the user
   * 
   * Calling this function may redirect the user to Authorization-Endpoint
   * Please make sure that you keep all state at a safe place!
   * 
   * @access public
   * @return bool
   **/
  self.jOAuth2.prototype.authorize = function () {
    // Check if we just received a response
    if ((window.location.hash.length > 1) &&
        ((window.location.hash.indexOf ('access_token=') > 0) ||
         (window.location.hash.indexOf ('error') > 0))) {
      var hash = window.location.hash.substring (1).split ('&');
      var params = { };
      var p;
      
      // Clear the hash
      history.pushState ('', document.title, window.location.pathname + window.location.search);
      
      // Parse contents of hash
      for (var i = 0; i < hash.length; i++)
        if ((p = hash [i].indexOf ('=')) > 0)
          params [decodeURIComponent (hash [i].substring (0, p).replace (/\+/, '%20'))] = decodeURIComponent (hash [i].substring (p + 1).replace (/\+/, '%20'));
      
      // Check for a valid token
      if ((typeof params.access_token != 'undefined') &&
          (typeof params.token_type != 'undefined') &&
          (typeof params.state != 'undefined') &&
          (params.token_type == 'Bearer') &&
          (params.state == this.options.storage_id)) {
        // Append time of issuance
        params.issued_at = Date.now ();
        
        if (params.expires_in)
          params.expires_in = parseInt (params.expires_in) * 1000;
        else
          params.expires_in = this.options.expires_default;
        
        params.expires_at = params.issued_at + params.expires_in;
        
        // Post-Process scops
        if (typeof params.scope != 'undefined')
          params.scopes = params.scope.split (' ');
        
        // Store the token
        this.token = params;
        this.options.storage.setItem ('jOAuth2-Token-' + this.options.storage_id, JSON.stringify (this.token));
        
        // Run authorize-callback
        if (this.options.onauthorize)
          this.options.onauthorize.apply (this, [ params ]);
        
      // Check for an error
      } else if ((typeof params.error != 'undefined') &&
          (typeof params.state != 'undefined') &&
          (params.state == this.options.storage_id)) {
        // Run error-callback
        if (this.options.onerror)
          this.options.onerror.apply (this, [ params.error, params ]);
        
        if (!this.check ())
          return false;
      
      // Bail out some kind of error here
      } else {
        console.log ('Received invalid access-token?');
        console.log (params);
        
        if (!this.check ())
          return false;
      }
    }
    
    // Check if we have a token stored
    if (this.check ()) {
      var jOAuth2 = this;
      var token = this.getToken ();
      var token_lifetime = token.expires_at - Date.now ();
      
      window.setTimeout (function () {
        if (jOAuth2.options.onexpiration)
          jOAuth2.options.onexpiration.apply (jOAuth2, [ token ]);
      }, token_lifetime);
      
      window.setTimeout (function () {
        if (jOAuth2.options.onexpiration_warning)
          jOAuth2.options.onexpiration_warning.apply (jOAuth2, [ token, token.expires_at - Date.now () ]);
      }, Math.max (token_lifetime - 900000, parseInt (token_lifetime - (token.expires_in / 4))));
      
      return true;
    }
    
    // Try to redirect to authz-endpoint
    this.reauthorize ();
    
    return false;
  };
  // }}}
  
  // {{{ reauthorize
  /**
   * Try to renew the last token
   * 
   * @access public
   * @return void
   **/
  self.jOAuth2.prototype.reauthorize = function () {
    // Try to access our previous token
    var token = this.getToken ();
    
    // Check if all required options are in place
    if (this.options.authorization_endpoint == null)
      throw 'Missing URL for authorization-endpoint';

    if (this.options.client_id == null)
      throw 'Missing client-id for authorization';

    // Generate redirect-uri
    var uri = this.options.redirect_uri;
    
    if (!uri) {
      uri = window.location.href;
      
      if (uri.indexOf ('#') >= 0)
        uri = uri.substring (0, uri.indexOf ('#'));
    }
     
    // Run early callback
    if (this.options.onbeforeauthorize && (this.options.onbeforeauthorize.apply (this, [ ]) === false))
      return;
    
    // Prepare parameters
    var params = {
      response_type : 'token',
      client_id : this.options.client_id,
      redirect_uri : uri,
      state : this.options.storage_id
    };
    
    if (this.options.scopes)
      params.scope = this.options.scopes.join (' ');
    
    if (token) {
      params.last_token = token.access_token;
      
      if (token.scopes && token.scopes.length > 1)
        params.scope = token.scopes.join (' ');
    }
    
    // Redirect to authorization-endpoint
    // TODO: This should be POST?
    window.location.href = addurlp (this.options.authorization_endpoint, params);
  };
  // }}}
  
  // {{{ check
  /**
   * Check the state of the current granted token
   * 
   * @access public
   * @return bool
   **/
  self.jOAuth2.prototype.check = function () {
    // Retrive the current token
    var token = this.getToken ();
    
    if (!token)
      return false;
    
    // Check if the token has expires
    if (Date.now () < token.expires_at)
      return true;
    
    // Check the validity by introspection
    if (this.options.introspection_endpoint != null) {
      // Request token-introspection (SYNCHRONOUS!!!)
      var xhr = new XMLHttpRequest ();
      
      if (this.options.introspection_method == 'rfc') {
        xhr.open ('post', this.options.introspection_endpoint, false);
        
        xhr.setRequestHeader ('Content-Type', 'application/x-www-form-urlencoded');
        this.patchXHR (xhr);
        
        xhr.send ('token=' + escape (token.access_token));
      } else {
        xhr.open ('get', this.options.introspection_endpoint + '/' + token.access_token, false);
        this.patchXHR (xhr);
        
        xhr.send ();
      }
       
      // Process the result
      if ((xhr.getResponseHeader ('Content-Type') == 'application/json') ||
          (xhr.getResponseHeader ('Content-Type') == 'text/json')) {
        var result = JSON.parse (xhr.response);
        
        if (result.active)
          return true;
      }
    }
    
    // Remove the token
    this.token = null; 
    this.options.storage.removeItem ('jOAuth2-Token-' + this.options.storage_id);
    
    return false;
  };
  // }}}
  
  // {{{ getAuthorizationHeaders
  /**
   * Retrive all headers and their contents needed for authentication against
   * a resource-server
   * 
   * @access public
   * @return object
   **/
  self.jOAuth2.prototype.getAuthorizationHeaders = function () {
    // Retrive the current token
    var token = this.getToken ();
    
    if (!token)
      throw 'No token available';
    
    return {
      'Authorization' : 'Bearer ' + token.access_token
    };
  };
  // }}}
  
  // {{{ patchXHR
  /**
   * Prepare an XHR-Object to be used with our authorization
   * 
   * @param object xhr
   * 
   * @access public
   * @return void
   **/
  self.jOAuth2.prototype.patchXHR = function (xhr) {
    var h = this.getAuthorizationHeaders ();
    
    for (var p in h)
      xhr.setRequestHeader (p, h [p]);
  };
  // }}}
})();
