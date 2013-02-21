<?php

namespace Escape\WSSEAuthenticationBundle\Tests\Security\Http\EntryPoint;

use Escape\WSSEAuthenticationBundle\Security\Http\EntryPoint\EntryPoint;

use Symfony\Component\Security\Core\Exception\AuthenticationException;

class EntryPointTest extends \PHPUnit_Framework_TestCase
{
    protected function setUp()
    {
        if(!interface_exists('Symfony\Component\HttpKernel\Log\LoggerInterface'))
        {
            $this->markTestSkipped('The "HttpKernel" component is not available');
        }

        if(!class_exists('Symfony\Component\HttpFoundation\Request'))
        {
            $this->markTestSkipped('The "HttpFoundation" component is not available');
        }
    }

    public function testStart()
    {
        $logger = $this->getMock('Symfony\Component\HttpKernel\Log\LoggerInterface');
        $request = $this->getMock('Symfony\Component\HttpFoundation\Request');
        $realm = 'TheRealm';
        $profile = 'TheProfile';

        $authenticationException = new AuthenticationException('TheAuthenticationExceptionMessage');

        $entryPoint = new EntryPoint($logger,$realm,$profile);
        $response = $entryPoint->start($request, $authenticationException);

        $this->assertEquals(401, $response->getStatusCode());

        $this->assertRegExp(
            sprintf(
                '/^WSSE realm="%s", profile="%s"$/',
                $realm,
                $profile
            ),
            $response->headers->get('WWW-Authenticate')
        );
    }

    public function testStartWithNoException()
    {
        $logger = $this->getMock('Symfony\Component\HttpKernel\Log\LoggerInterface');
        $request = $this->getMock('Symfony\Component\HttpFoundation\Request');
        $realm = 'TheRealm';
        $profile = 'TheProfile';

        $entryPoint = new EntryPoint($logger,$realm,$profile);
        $response = $entryPoint->start($request);

        $this->assertEquals(401, $response->getStatusCode());

        $this->assertRegExp(
            sprintf(
                '/^WSSE realm="%s", profile="%s"$/',
                $realm,
                $profile
            ),
            $response->headers->get('WWW-Authenticate')
        );
    }
}