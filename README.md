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

### Refactoring
    * Change in directory structure, similar to structure of Symfony2 core authentication methods