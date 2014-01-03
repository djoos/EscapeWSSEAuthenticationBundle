<?php

namespace Escape\WSSEAuthenticationBundle\Tests\DependencyInjection\Security\Factory;

use Escape\WSSEAuthenticationBundle\DependencyInjection\Security\Factory\Factory;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

class FactoryTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function getPosition()
    {
        $factory = new Factory();
        $result = $factory->getPosition();
        $this->assertEquals('pre_auth', $result);
    }

    /**
     * @test
     */
    public function getKey()
    {
        $factory = new Factory();
        $result = $factory->getKey();
        $this->assertEquals('wsse', $result);
        $this->assertEquals('wsse', $this->getFactory()->getKey());
    }

    protected function getFactory()
    {
        return $this->getMockForAbstractClass('Escape\WSSEAuthenticationBundle\DependencyInjection\Security\Factory\Factory', array());
    }

    public function testCreate()
    {
        $factory = $this->getFactory();

        $container = new ContainerBuilder();
        $container->register('escape_wsse_authentication.provider');

        $realm = 'TheRealm';
        $profile = 'TheProfile';
        $lifetime = 300;

        $algorithm = 'sha1';
        $encodeHashAsBase64 = true;
        $iterations = 1;

        $encoder = array(
            'algorithm' => $algorithm,
            'encodeHashAsBase64' => $encodeHashAsBase64,
            'iterations' => $iterations
        );

        list($authProviderId,
             $listenerId,
             $entryPointId
        ) = $factory->create(
            $container,
            'foo',
            array(
                'realm' => $realm,
                'profile' => $profile,
                'encoder' => $encoder,
                'lifetime' => $lifetime
            ),
            'user_provider',
            'entry_point'
        );

        //encoder
        $encoderId = $factory->getEncoderId();

        $this->assertEquals('escape_wsse_authentication.encoder.foo', $encoderId);
        $this->assertTrue($container->hasDefinition('escape_wsse_authentication.encoder.foo'));

        $definition = $container->getDefinition('escape_wsse_authentication.encoder.foo');
        $this->assertEquals(
            array(
                'index_0' => $algorithm,
                'index_1' => $encodeHashAsBase64,
                'index_2' => $iterations
            ),
            $definition->getArguments()
        );

        //nonce cache
        $nonceCacheId = $factory->getNonceCacheId();

        $this->assertEquals('escape_wsse_authentication.nonce_cache.foo', $nonceCacheId);
        $this->assertTrue($container->hasDefinition('escape_wsse_authentication.nonce_cache.foo'));

        //auth provider
        $this->assertEquals('escape_wsse_authentication.provider.foo', $authProviderId);
        $this->assertTrue($container->hasDefinition('escape_wsse_authentication.provider.foo'));

        $definition = $container->getDefinition('escape_wsse_authentication.provider.foo');
        $this->assertEquals(
            array(
                'index_0' => new Reference('user_provider'),
                'index_1' => new Reference($encoderId),
                'index_2' => new Reference($nonceCacheId),
                'index_3' => $lifetime
            ),
            $definition->getArguments()
        );

        //listener
        $this->assertEquals('escape_wsse_authentication.listener.foo', $listenerId);
        $this->assertTrue($container->hasDefinition('escape_wsse_authentication.listener.foo'));

        $definition = $container->getDefinition('escape_wsse_authentication.listener.foo');
        $this->assertEquals(
            array(
                0 => new Reference($entryPointId)
            ),
            $definition->getArguments()
        );

        //entry point
        $this->assertEquals('escape_wsse_authentication.entry_point.foo', $entryPointId);
        $this->assertTrue($container->hasDefinition('escape_wsse_authentication.entry_point.foo'));

        $definition = $container->getDefinition('escape_wsse_authentication.entry_point.foo');
        $this->assertEquals(
            array(
                'index_1' => $realm,
                'index_2' => $profile
            ),
            $definition->getArguments()
        );
    }
}
