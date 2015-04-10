<?php

$file = __DIR__.'/../vendor/autoload.php';

if(!file_exists($file))
{
    throw new RuntimeException('Install dependencies to run test suite. "php composer.phar install --dev"');
}

require_once $file;

// disable the deprecation warnings
PHPUnit_Framework_Error_Deprecated::$enabled = FALSE;
