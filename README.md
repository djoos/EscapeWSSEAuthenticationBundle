[![Build Status](https://secure.travis-ci.org/escapestudios/EscapeWSSEAuthenticationBundle.png)](http://travis-ci.org/escapestudios/EscapeWSSEAuthenticationBundle)

## Introduction

The EscapeWSSEAuthentication bundle is a simple and easy way to implement WSSE authentication in Symfony2 applications

## Installation

composer.json

```
"require": {
    ...
    "escapestudios/wsse-authentication-bundle": "2.3.x-dev",
    ...
}
```

app/AppKernel.php

```
public function registerBundles()
{
    return array(
        //...
        new Escape\WSSEAuthenticationBundle\EscapeWSSEAuthenticationBundle(),
        //...
    );
    ...
```

## Commands

Delete expired nonces via the ``escape:wsseauthentication:nonces:delete`` command that ships with this bundle; it takes the firewall name as a (required) parameter.

``php app/console --env=dev escape:wsseauthentication:nonces:delete wsse_secured``

## Usage example

app/config/security.yml

```
firewalls:
    wsse_secured:
        pattern:   ^/api/.*
        wsse:
            realm: "Secured API" #identifies the set of resources to which the authentication information will apply (WWW-Authenticate)
            profile: "UsernameToken" #WSSE profile (WWW-Authenticate)
            lifetime: 300 #lifetime of nonce
```

...that's it! You can now start calling your API endpoints: generate a X-WSSE header (Symfony\Component\Security\Core\Encoder\MessageDigestPasswordEncoder) and add it to your request (cUrl).

## Advanced configuration

### Specify a custom digest algorithm

app/config/security.yml

```
firewalls:
    wsse_secured:
        #...
        wsse:
            #...
            encoder: #digest algorithm
                algorithm: sha1
                encodeHashAsBase64: true
                iterations: 1
```

### Specify a custom nonce cache

app/config/security.yml

```
services:
    #...
    cache_nonces:
        class: Doctrine\Common\Cache\PhpFileCache
        arguments: [%kernel.cache_dir%/path/to/nonces]
```

app/config/security.yml

```
firewalls:
    wsse_secured:
        #...
        wsse:
            #...
            nonce_cache_service_id: cache_nonces
```

### Specify custom authentication class(es)

app/config/config.yml

```
# Escape WSSE authentication configuration
escape_wsse_authentication:
    authentication_provider_class: Escape\WSSEAuthenticationBundle\Security\Core\Authentication\Provider\Provider
    authentication_listener_class: Escape\WSSEAuthenticationBundle\Security\Http\Firewall\Listener
    authentication_entry_point_class: Escape\WSSEAuthenticationBundle\Security\Http\EntryPoint\EntryPoint
    authentication_encoder_class: Symfony\Component\Security\Core\Encoder\MessageDigestPasswordEncoder
```
