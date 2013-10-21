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

Delete expired nonces via the ``escape:wsseauthentication:nonces:delete`` command that ships with this bundle; it takes nonceDir and lifetime as (required) parameters.

``php app/console --env=dev escape:wsseauthentication:nonces:delete /path/to/security/nonces 300``

## Usage example

app/config/security.yml

nonce_dir: location where nonces will be saved (use null to skip nonce-validation)
lifetime: lifetime of nonce
realm: identifies the set of resources to which the authentication information will apply (WWW-Authenticate)
profile: WSSE profile (WWW-Authenticate)

```
firewalls:
    wsse_secured:
        pattern:   ^/api/.*
        wsse:
            nonce_dir: null
            lifetime: 300
            realm: "Secured API"
            profile: "UsernameToken"
```

## Advanced configuration

### Specify custom authentication class(es)

app/config/config.yml

```
# Escape WSSE authentication configuration
escape_wsse_authentication:
    authentication_provider_class: Escape\WSSEAuthenticationBundle\Security\Core\Authentication\Provider\Provider
    authentication_listener_class: Escape\WSSEAuthenticationBundle\Security\Http\Firewall\Listener
    authentication_entry_point_class: Escape\WSSEAuthenticationBundle\Security\Http\EntryPoint\EntryPoint
```

### Specify an encoder of choice (digest algorithm)

app/config/security.yml

```
encoders:
    Symfony\Component\Security\Core\User\User:
        algorithm: sha1
        iterations: 1
        encode_as_base64: true
```

FYI: 1 iteration SHA1 encoded as base64 was the digest algorithm previously hard-coded into the bundle.