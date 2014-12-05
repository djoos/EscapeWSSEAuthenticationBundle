<?php

namespace Escape\WSSEAuthenticationBundle\DependencyInjection\Security\Factory;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;

class Factory implements SecurityFactoryInterface
{
    private $encoderId;
    private $nonceCacheId;

    public function create(ContainerBuilder $container, $id, $config, $userProviderId, $defaultEntryPoint)
    {
        $this->encoderId = 'escape_wsse_authentication.encoder.'.$id;

        $container->setDefinition($this->encoderId, new DefinitionDecorator('escape_wsse_authentication.encoder'));

        if(isset($config['encoder']['algorithm']))
        {
            $container->getDefinition($this->encoderId)->replaceArgument(0, $config['encoder']['algorithm']);
        }

        if(isset($config['encoder']['encodeHashAsBase64']))
        {
            $container->getDefinition($this->encoderId)->replaceArgument(1, $config['encoder']['encodeHashAsBase64']);
        }

        if(isset($config['encoder']['iterations']))
        {
            $container->getDefinition($this->encoderId)->replaceArgument(2, $config['encoder']['iterations']);
        }

        if(isset($config['nonce_cache_service_id']))
        {
            $this->nonceCacheId = $config['nonce_cache_service_id'];
        }
        else
        {
            $this->nonceCacheId = 'escape_wsse_authentication.nonce_cache.'.$id;

            $container->setDefinition($this->nonceCacheId, new DefinitionDecorator('escape_wsse_authentication.nonce_cache'));
        }

        $providerId = 'escape_wsse_authentication.provider.'.$id;

        $container
            ->setDefinition($providerId, new DefinitionDecorator('escape_wsse_authentication.provider'))
            ->replaceArgument(0, new Reference($userProviderId))
            ->replaceArgument(1, $id)
            ->replaceArgument(2, new Reference($this->encoderId))
            ->replaceArgument(3, new Reference($this->nonceCacheId))
            ->replaceArgument(4, $config['lifetime'])
            ->replaceArgument(5, $config['date_format']);

        $entryPointId = $this->createEntryPoint($container, $id, $config, $defaultEntryPoint);

        $listenerId = 'escape_wsse_authentication.listener.'.$id;

        $container
            ->setDefinition($listenerId, new DefinitionDecorator('escape_wsse_authentication.listener'))
            ->addArgument($id)
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

    public function getEncoderId()
    {
        return $this->encoderId;
    }

    public function getNonceCacheId()
    {
        return $this->nonceCacheId;
    }

    public function addConfiguration(NodeDefinition $node)
    {
        $node
            ->children()
                ->scalarNode('provider')->end()
                ->scalarNode('realm')->defaultValue(null)->end()
                ->scalarNode('profile')->defaultValue('UsernameToken')->end()
                ->scalarNode('lifetime')->defaultValue(300)->end()
                ->scalarNode('date_format')->defaultValue(
                    '/^([\+-]?\d{4}(?!\d{2}\b))((-?)((0[1-9]|1[0-2])(\3([12]\d|0[1-9]|3[01]))?|W([0-4]\d|5[0-2])(-?[1-7])?|(00[1-9]|0[1-9]\d|[12]\d{2}|3([0-5]\d|6[1-6])))([T\s]((([01]\d|2[0-3])((:?)[0-5]\d)?|24\:?00)([\.,]\d+(?!:))?)?(\17[0-5]\d([\.,]\d+)?)?([zZ]|([\+-])([01]\d|2[0-3]):?([0-5]\d)?)?)?)?$/'
                )->end()
                ->arrayNode('encoder')
                    ->children()
                        ->scalarNode('algorithm')->end()
                        ->scalarNode('encodeHashAsBase64')->end()
                        ->scalarNode('iterations')->end()
                    ->end()
                ->end()
                ->scalarNode('nonce_cache_service_id')->defaultValue(null)->end()
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
