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

        $nonce_dir = 'nonce';
        $lifetime = 300;
        $realm = 'TheRealm';
        $profile = 'TheProfile';
        $futurnTokenCheck = true;

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
                'nonce_dir' => $nonce_dir,
                'lifetime' => $lifetime,
                'realm' => $realm,
                'profile' => $profile,
                'encoder' => $encoder,
                'future_token_check' => $futurnTokenCheck
            ),
            'user_provider',
            'entry_point'
        );

        $encoderId = $factory->getEncoderId();

        //encoder
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

        //auth provider
        $this->assertEquals('escape_wsse_authentication.provider.foo', $authProviderId);
        $this->assertTrue($container->hasDefinition('escape_wsse_authentication.provider.foo'));

        $definition = $container->getDefinition('escape_wsse_authentication.provider.foo');
        $this->assertEquals(
            array(
                'index_0' => new Reference('user_provider'),
                'index_1' => new Reference($encoderId),
                'index_2' => $nonce_dir,
                'index_3' => $lifetime,
                'index_4' => $futurnTokenCheck
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
