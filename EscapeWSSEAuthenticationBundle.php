<?php

namespace Mayflower\WSSEAuthenticationBundle;

use Symfony\Component\HttpKernel\Bundle\Bundle;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Mayflower\WSSEAuthenticationBundle\DependencyInjection\Security\Factory\Factory;

class MayflowerWSSEAuthenticationBundle extends Bundle
{
	  public function build(ContainerBuilder $container)
	  {
		  parent::build($container);

		  $extension = $container->getExtension('security');
		  $extension->addSecurityListenerFactory(new Factory());
	  }
}
