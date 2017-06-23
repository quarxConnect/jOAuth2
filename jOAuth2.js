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
      scope : null,
      storage : window.sessionStorage,
      storage_id : 'default'
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
        (window.location.hash.indexOf ('access_token=') > 0)) {
      var hash = window.location.hash.substring (1).split ('&');
      var params = { };
      var p;
      
      // Clear the hash
      window.location.hash = '';
      
      // Parse contents of hash
      for (var i = 0; i < hash.length; i++)
        if ((p = hash [i].indexOf ('=')) > 0)
          params [unescape (hash [i].substring (0, p))] = unescape (hash [i].substring (p + 1));
      
      // Validate contents
      if ((typeof params.access_token != 'undefined') &&
          (typeof params.token_type != 'undefined') &&
          (typeof params.state != 'undefined') &&
          (params.token_type == 'Bearer') &&
          (params.state == this.options.storage_id)) {
        // Append time of issuance
        params.issued_at = Date.now ();
        
        // Store the token
        this.token = params;
        this.options.storage.setItem ('jOAuth2-Token-' + this.options.storage_id, JSON.stringify (this.token));
        
        return true;
      }
      
      // Bail out some kind of error here
      console.log ('Received invalid access-token?');
      console.log (params);
    }
    
    // Check if we have a token stored
    if (this.check ())
      return true;
    
    // Check if all required options are in place
    if (this.options.authorization_endpoint == null)
      throw 'Missing URL for authorization-endpoint';
    
    if (this.options.client_id == null)
      throw 'Missing client-id for authorization';
    
    // Redirect to authorization-endpoint
    // TODO: This should be POST
    window.location.href = addurlp (
      this.options.authorization_endpoint,
      {
        response_type : 'token',
        client_id : this.options.client_id,
        redirect_uri : this.options.redirect_uri || window.location.href,
        scope : this.options.scope,
        state : this.options.storage_id
      }
    );
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
    
    // Check the validity by expires-in
    if (typeof token.expires_in != 'undefined') {
      if (Date.now () < (parseInt (token.expires_in) * 1000) + token.issued_at)
        return true;
    
    // Check the validity by introspection
    } else if (this.options.introspection_endpoint != null) {
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
