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

## Quick usage example

app/config/security.yml

```
firewalls:
    wsse_secured:
        pattern:   ^/api/.*
        wsse:
            realm: "Secured with WSSE" #identifies the set of resources to which the authentication information will apply (WWW-Authenticate)
            profile: "UsernameToken" #WSSE profile (WWW-Authenticate)
```

...that's it! Your "wsse_secured"-firewall is now secured via the (out-of-the-box) WSSE Authentication setup. You can now start calling your API endpoints: generate a X-WSSE header (Symfony\Component\Security\Core\Encoder\MessageDigestPasswordEncoder) and add it to your request (cUrl).
It is strongly recommended to have a read through the more advanced configuration below once you're up and running with the basics...

## Advanced configuration

### Specify a custom token lifetime, default: 300

app/config/security.yml

```
firewalls:
    wsse_secured:
        #...
        wsse:
            #...
            lifetime: 300
```

### Specify a custom date format, default: see regular expression below for ISO8601 (check out http://www.pelagodesign.com/blog/2009/05/20/iso-8601-date-validation-that-doesnt-suck/)

app/config/security.yml

```
firewalls:
    wsse_secured:
        #...
        wsse:
            #...
            date_format: '/^([\+-]?\d{4}(?!\d{2}\b))((-?)((0[1-9]|1[0-2])(\3([12]\d|0[1-9]|3[01]))?|W([0-4]\d|5[0-2])(-?[1-7])?|(00[1-9]|0[1-9]\d|[12]\d{2}|3([0-5]\d|6[1-6])))([T\s]((([01]\d|2[0-3])((:?)[0-5]\d)?|24\:?00)([\.,]\d+(?!:))?)?(\17[0-5]\d([\.,]\d+)?)?([zZ]|([\+-])([01]\d|2[0-3]):?([0-5]\d)?)?)?)?$/'
```

### Specify a custom digest algorithm, default: base 64-encoded sha1 with 1 iteration

!!! please do change the digest algorithm to a stronger one than the default one !!!

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

### Specify a custom nonce cache, default: Doctrine\Common\Cache\PhpFileCache in %kernel.cache_dir%/security/nonces

app/config/security.yml

```
services:
    #...
    cache_nonces:
        class: Doctrine\Common\Cache\PhpFileCache
        arguments: [%kernel.cache_dir%/security/nonces]
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

### Use multiple providers

app/config/security.yml

```
providers:
    provider_one:
        #...
    provider_two:
        #...

firewalls:
    wsse_secured_by_provider_one:
        provider: provider_one
        wsse:
            #...

    wsse_secured_by_provider_two:
        provider: provider_two
        wsse:
            #...
```

### Make use of a specific user provider on a firewall with WSSE as one of multiple authentication mechanisms

app/config/security.yml

```
providers:
    users:
        #...
    wsse_users:
        memory:
            users:
                - { name: 'someuser', password: 'somesecret' }

firewalls:
    secured:
        provider: users
        wsse:
            #...
            provider: wsse_users #don't make use of firewall's "users"-provider, but "wsse_users"-provider for WSSE
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
