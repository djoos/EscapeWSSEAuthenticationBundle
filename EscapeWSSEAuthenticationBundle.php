<?php

namespace Escape\WSSEAuthenticationBundle;

use Symfony\Component\HttpKernel\Bundle\Bundle;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Escape\WSSEAuthenticationBundle\DependencyInjection\Security\Factory\Factory;

class EscapeWSSEAuthenticationBundle extends Bundle
{
      public function build(ContainerBuilder $container)
      {
          parent::build($container);

          $extension = $container->getExtension('security');
          $extension->addSecurityListenerFactory(new Factory());
      }
}
