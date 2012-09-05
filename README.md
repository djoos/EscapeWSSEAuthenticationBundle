## Introduction

The EscapeWSSEAuthentication bundle is a simple and easy way to implement WSSE authentication into Symfony2 applications

## Installation

app/autoload.php

```
$loader->registerNamespaces(array(
    //other namespaces
    'Escape' => __DIR__.'/../vendor/bundles',
  ));
```

app/AppKernel.php

```
public function registerBundles()
{
    return array(
        //other bundles
        new Escape\WSSEAuthenticationBundle\EscapeWSSEAuthenticationBundle(),
    );
    ...
```

## Configuration

app/config/config.yml

```
# Escape Rackspace Cloud Files configuration
escape_wsse_authentication:
    provider_class: Escape\WSSEAuthenticationBundle\Security\Core\Authentication\Provider\Provider
    listener_class: Escape\WSSEAuthenticationBundle\Security\Http\Firewall\Listener
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

factories:
    - "%kernel.root_dir%/../vendor/bundles/Escape/WSSEAuthenticationBundle/Resources/config/security_factories.yml"
```

## Changelog

### 09/2012
    * Refactoring: changes to directory structure, replicating Symfony2 core authentication methods.

### 08/2012
    * WSSEFactory -> Factory
    * Fix wrong README reference
    * There's no WSSEFactory - use Factory instead

### 04/2012
    * README-fix
    * making the formatting consistent

### 02/2012
    * Refactoring. Improved method of parsing the header.

### 12/2011
    * Fixed fatal error. Commit unit tests
    * AbstractToken set to a $authenticated flag is false. It must be set true after authentication for successful authorization. This is done for all other symfony tokens.
    * It makes no sense to encode in base64 time and security by following the standards WSSE
    * initial version

## Contributors
    * Dmitry Petrov <dmitry.petrov@opensoftdev.ru>
    * David Joos <david@escapestudios.com>