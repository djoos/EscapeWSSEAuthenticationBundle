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
        	->end()
        ;

        return $treeBuilder;
    }
}