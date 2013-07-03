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

## Configuration

app/config/config.yml

```
# Escape WSSE authentication configuration
escape_wsse_authentication:
    authentication_provider_class: Escape\WSSEAuthenticationBundle\Security\Core\Authentication\Provider\Provider
    authentication_listener_class: Escape\WSSEAuthenticationBundle\Security\Http\Firewall\Listener
    authentication_entry_point_class: Escape\WSSEAuthenticationBundle\Security\Http\EntryPoint\EntryPoint
```

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
        wsse:      { nonce_dir: null, lifetime: 300, realm: "Secured API", profile: "UsernameToken" } 
```
