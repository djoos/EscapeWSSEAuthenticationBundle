<?php

namespace Escape\WSSEAuthenticationBundle\DependencyInjection\Security\Factory;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;

class Factory implements SecurityFactoryInterface
{
    public function create(ContainerBuilder $container, $id, $config, $userProviderId, $defaultEntryPoint)
    {
        $providerId = 'escape_wsse_authentication.provider.'.$id;

        $container
            ->setDefinition($providerId, new DefinitionDecorator('escape_wsse_authentication.provider'))
            ->replaceArgument(0, new Reference($userProviderId))
            ->replaceArgument(1, $config['nonce_dir'])
            ->replaceArgument(2, $config['lifetime']);

        $entryPointId = $this->createEntryPoint($container, $id, $config, $defaultEntryPoint);

        $listenerId = 'escape_wsse_authentication.listener.'.$id;

        $container
            ->setDefinition($listenerId, new DefinitionDecorator('escape_wsse_authentication.listener'))
            ->addArgument(new Reference($entryPointId));

        return array($providerId, $listenerId, $entryPointId);
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
                ->scalarNode('realm')->defaultValue(null)->end()
                ->scalarNode('profile')->defaultValue('UsernameToken')->end()
            ->end();
    }

    protected function createEntryPoint($container, $id, $config, $defaultEntryPoint)
    {
        $entryPointId = 'escape_wsse_authentication.entry_point.'.$id;

        $container
            ->setDefinition($entryPointId, new DefinitionDecorator('escape_wsse_authentication.entry_point'))
            ->replaceArgument(1, $config['realm'])
            ->replaceArgument(2, $config['profile']);

        return $entryPointId;
    }
}
