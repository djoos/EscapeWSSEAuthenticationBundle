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
    		    ->scalarNode('provider_class')->defaultValue('Escape\WSSEAuthenticationBundle\Security\Authentication\Provider\WsseAuthenticationProvider')->end()
        		->scalarNode('listener_class')->defaultValue('Escape\WSSEAuthenticationBundle\Security\Firewall\WsseListener')->end()
        		->scalarNode('factory_class')->defaultValue('Escape\WSSEAuthenticationBundle\Security\Factory\WsseFactory')->end()
        	->end()
        ;

        return $treeBuilder;
    }
}