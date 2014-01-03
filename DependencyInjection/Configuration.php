<?php

namespace Escape\WSSEAuthenticationBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root('escape_wsse_authentication');

        $rootNode
            ->children()
                ->scalarNode('authentication_provider_class')->defaultValue('Escape\WSSEAuthenticationBundle\Security\Core\Authentication\Provider\Provider')->end()
                ->scalarNode('authentication_listener_class')->defaultValue('Escape\WSSEAuthenticationBundle\Security\Http\Firewall\Listener')->end()
                ->scalarNode('authentication_entry_point_class')->defaultValue('Escape\WSSEAuthenticationBundle\Security\Http\EntryPoint\EntryPoint')->end()
                ->scalarNode('authentication_encoder_class')->defaultValue('Symfony\Component\Security\Core\Encoder\MessageDigestPasswordEncoder')->end()
                ->scalarNode('authentication_nonce_cache_class')->defaultValue('Doctrine\Common\Cache\PhpFileCache')->end()
            ->end();

        return $treeBuilder;
    }
}