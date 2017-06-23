# jOAuth2
Simple Javascript-Library to maintain OAuth2 implicit Grants

## Usage
~~~ {.html}
<script type="text/javascript">

  var authz = new jOAuth2 ({    
    client_id : 'id-of-public-client',
    authorization_endpoint : 'https://url-of-authz-endpoint/',
  });
  
  authz.authorize ();
</script>
~~~

`authorize()` may redirect the UA to the authorization-endpoint if
there is no or only an invalid access-token available. Whenever
possible it will try to check validity of access-tokens without any
external API-Call by using the `expires_in`-attribute from the original
grant. If `expires_in` is unavailable for any reason it may use
Token-Introspection (RFC 7662) to check the validity of an
access-token.

## Copyright & License
Copyright (C) 2017 Bernd Holzmüller

Licensed under the MIT License. This is free software: you are free to
change and redistribute it. There is NO WARRANTY, to the extent
permitted by law.
