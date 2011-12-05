## Introduction

The EscapeRackspaceCloudFiles bundle is a simple and easy way to use the namespaced version of php-cloudfiles with Symfony2 applications

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
escape_wsseauthentication:
    provider_class: Escape\WSSEAuthenticationBundle\Security\Authentication\Provider\Provider
    listener_class: Escape\WSSEAuthenticationBundle\Security\Firewall\Listener
    factory_class: Escape\WSSEAuthenticationBundle\Security\Factory\WSSEFactory
```

## Usage example

app/config/security.yml

```
firewalls:
    wsse_secured:
        pattern:   ^/api/.*
        wsse:      true

factories:
    - "%kernel.root_dir%/../vendor/bundles/Escape/WSSEAuthenticationBundle/Resources/config/security_factories.yml"
```