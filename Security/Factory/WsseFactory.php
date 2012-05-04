<?php

namespace Escape\WSSEAuthenticationBundle\Security\Factory;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AbstractFactory;

class WsseFactory extends AbstractFactory
{
	protected function createAuthProvider(ContainerBuilder $container, $id, $config, $userProviderId)
	{
		$authProviderId = 'escape_wsse.authentication.'.$id;

		$definition = $container
			->setDefinition($authProviderId, new DefinitionDecorator('escape_wsse.authentication'))
			->replaceArgument(0, $id)
			->replaceArgument(1, $config['nonce_dir'])
			->replaceArgument(2, $config['lifetime'])
			->addArgument(new Reference($userProviderId))
			->addArgument(new Reference('security.user_checker'));

		return $authProviderId;
	}

	protected function getListenerId()
	{
		return 'escape_wsse.security.authentication.listener';
	}
    protected function isRememberMeAware($config)
    {
        return false;
    }

	public function getPosition()
	{
		return 'pre_auth';
	}

	public function getKey()
	{
		return 'wsse';
	}

	public function addConfiguration(NodeDefinition $node)
	{
		$node
			->children()
				->scalarNode('nonce_dir')->defaultValue(null)->end()
				->scalarNode('lifetime')->defaultValue(300)->end()
				->scalarNode('provider')->end()
			->end()
		;
	}
}