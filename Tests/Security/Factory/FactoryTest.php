<?php
/**
 * @author Dmitry Petrov <dmitry.petrov@opensoftdev.ru>
 */
namespace Escape\WSSEAuthenticationBundle\Tests\Security\Factory;

use Escape\WSSEAuthenticationBundle\Security\Factory\Factory;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * @author Dmitry Petrov <dmitry.petrov@opensoftdev.ru>
 */
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
        return $this->getMockForAbstractClass('Escape\WSSEAuthenticationBundle\Security\Factory\Factory', array());
    }

    public function testCreate()
    {
        $factory = $this->getFactory();

        $container = new ContainerBuilder();
        $container->register('wsse.security.authentication.provider');

        list($authProviderId,
             $listenerId,
             $entryPointId
        ) = $factory->create($container, 'foo', array('nonce_dir' => 'nonce', 'lifetime' => 300), 'user_provider', 'entry_point');

        // auth provider
        $this->assertEquals('security.authentication.provider.wsse.foo', $authProviderId);
        $this->assertEquals('security.authentication.listener.wsse.foo', $listenerId);
        $this->assertEquals('entry_point', $entryPointId);
        $this->assertTrue($container->hasDefinition('security.authentication.listener.wsse.foo'));
        $definition = $container->getDefinition('security.authentication.provider.wsse.foo');
        $this->assertEquals(array('index_0' => new Reference('user_provider'), 'index_1' => 'nonce', 'index_2' => 300), $definition->getArguments());
        $this->assertTrue($container->hasDefinition('security.authentication.provider.wsse.foo'));
    }
}
