<?php

require_once $_SERVER['SYMFONY'].'/src/Symfony/Component/ClassLoader/UniversalClassLoader.php';

use Symfony\Component\ClassLoader\UniversalClassLoader;

$loader = new UniversalClassLoader();
$loader->registerNamespaces(
    array(
        'Symfony' => $_SERVER['SYMFONY'].'/src',
    )
);

$loader->register();

spl_autoload_register(function($class)
{
    $class = ltrim($class, '\\');

    if(0 === strpos($class, 'Escape\WSSEAuthenticationBundle\\'))
    {
        $file = __DIR__.'/../'.str_replace('\\', '/', substr($class, strlen('Escape\WSSEAuthenticationBundle\\'))).'.php';

        if(file_exists($file))
        {
            require $file;
        }
    }
});