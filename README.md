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
    provider_class: Escape\WSSEAuthenticationBundle\Security\Authentication\Provider\Provider
    listener_class: Escape\WSSEAuthenticationBundle\Security\Firewall\Listener
    factory_class: Escape\WSSEAuthenticationBundle\Security\Factory\WSSEFactory
```

## Usage example

app/config/security.yml

nonce_dir: location where nonces will be saved (use null to skip nonce-validation)
lifetime: lifetime of nonce
provider: user provider for wsse, optional, if not set first user provider configured will be used

```
firewalls:
    wsse_secured:
        pattern:   ^/api/.*
        wsse:
            nonce_dir: null
            lifetime: 300
            provider: my_user_provider

factories:
    - "%kernel.root_dir%/../vendor/bundles/Escape/WSSEAuthenticationBundle/Resources/config/security_factories.yml"
```
