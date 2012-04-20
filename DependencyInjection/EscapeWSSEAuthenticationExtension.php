<?php

namespace Escape\WSSEAuthenticationBundle\DependencyInjection;

use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\Config\FileLocator;

class EscapeWSSEAuthenticationExtension extends Extension
{
	public function load(array $configs, ContainerBuilder $container)
	{
		$configuration = new Configuration();
		$config = $this->processConfiguration($configuration, $configs);

		$loader = new YamlFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));
		$loader->load('services.yml');

		$container->setParameter('wsse.authentication.provider.class', $config['provider_class']);
		$container->setParameter('wsse.authentication.listener.class', $config['listener_class']);
		$container->setParameter('wsse.authentication.factory.class', $config['factory_class']);
		$container->setParameter('wsse.authentication.allowed_clients', $config['allowed_clients']);
	}
}