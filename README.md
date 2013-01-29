[![Build Status](https://secure.travis-ci.org/escapestudios/EscapeWSSEAuthenticationBundle.png)](http://travis-ci.org/escapestudios/MayflowerWSSEAuthenticationBundle)

## Introduction

The MayflowerWSSEAuthentication bundle is a simple and easy way to implement WSSE authentication in Symfony2 applications

## Installation

composer.json

```
"require": {
    ...
    "mayflower/wsse-authentication-bundle": "2.2.x-dev",
    ...
}
```

app/AppKernel.php

```
public function registerBundles()
{
    return array(
        //...
        new Mayflower\WSSEAuthenticationBundle\MayflowerWSSEAuthenticationBundle(),
        //...
    );
    ...
```

## Configuration

app/config/config.yml

```
# Mayflower WSSE authentication configuration
escape_wsse_authentication:
    authentication_provider_class: Mayflower\WSSEAuthenticationBundle\Security\Core\Authentication\Provider\Provider
    authentication_listener_class: Mayflower\WSSEAuthenticationBundle\Security\Http\Firewall\Listener
```

## Usage example

app/config/security.yml

nonce_dir: location where nonces will be saved (use null to skip nonce-validation)
lifetime: lifetime of nonce

```
firewalls:
    wsse_secured:
        pattern:   ^/api/.*
        wsse:      { nonce_dir: null, lifetime: 300 } 
```
