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

        $container->setParameter('escape_wsse_authentication.provider.class', $config['authentication_provider_class']);
        $container->setParameter('escape_wsse_authentication.listener.class', $config['authentication_listener_class']);
        $container->setParameter('escape_wsse_authentication.entry_point.class', $config['authentication_entry_point_class']);
        $container->setParameter('escape_wsse_authentication.encoder.class', $config['authentication_encoder_class']);
        $container->setParameter('escape_wsse_authentication.nonce_cache.class', $config['authentication_nonce_cache_class']);
    }

    //https://github.com/symfony/symfony/issues/1768#issuecomment-1653074
    //"However, if the default placement of underscores doesn't work for you,
    //you can simply overwrite Extension::getAlias() and Bundle::getContainerExtension()."
    public function getAlias()
    {
        return 'escape_wsse_authentication';
    }
}