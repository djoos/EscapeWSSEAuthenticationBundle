<?php

namespace Escape\WSSEAuthenticationBundle\Tests\Security\Http\Firewall;

use Escape\WSSEAuthenticationBundle\Security\Http\Firewall\Listener;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken as Token;

use Symfony\Component\HttpFoundation\Response;

class ListenerTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var \PHPUnit_Framework_MockObject_MockObject $responseEvent
     */
    private $responseEvent;

    /**
     * @var \PHPUnit_Framework_MockObject_MockObject
     */
    private $request;

    /**
     * @var \PHPUnit_Framework_MockObject_MockObject
     */
    private $securityContext;

    /**
     * @var \PHPUnit_Framework_MockObject_MockObject
     */
    private $authenticationManager;

    /**
     * @var \PHPUnit_Framework_MockObject_MockObject
     */
    private $authenticationEntryPoint;

    protected function setUp()
    {
        $this->responseEvent = $this->getMockBuilder('Symfony\Component\HttpKernel\Event\GetResponseEvent')->disableOriginalConstructor()->getMock();
        $this->request = $this->getMockForAbstractClass('Symfony\Component\HttpFoundation\Request');
        $this->responseEvent->expects($this->once())->method('getRequest')->will($this->returnValue($this->request));
        $this->securityContext = $this->getMock('Symfony\Component\Security\Core\SecurityContextInterface');
        $this->authenticationManager = $this->getMock('Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface');
        $this->authenticationEntryPoint = $this->getMock('Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface');
    }

    /**
     * @test
     */
    public function handleReturnToken()
    {
        $token = new Token('someuser', 'somedigest', 'someproviderkey');
        $token->setAttribute('nonce','somenonce');
        $token->setAttribute('created','2010-12-12 20:00:00');

        $tokenMock2 = $this->getMock('Symfony\Component\Security\Core\Authentication\Token\TokenInterface');
        $this->authenticationManager->expects($this->once())->method('authenticate')->with($token)->will($this->returnValue($tokenMock2));
        $this->securityContext->expects($this->once())->method('setToken')->with($tokenMock2);
        $this->request->headers->add(array('X-WSSE'=>'UsernameToken Username="someuser", PasswordDigest="somedigest", Nonce="somenonce", Created="2010-12-12 20:00:00"'));

        $listener = new Listener($this->securityContext, $this->authenticationManager, 'someproviderkey', $this->authenticationEntryPoint);
        $listener->handle($this->responseEvent);
    }

    /**
     * @test
     */
    public function handleReturnResponse()
    {
        $token = new Token('someuser', 'somedigest', 'someproviderkey');
        $token->setAttribute('nonce','somenonce');
        $token->setAttribute('created','2010-12-12 20:00:00');

        $response = new Response();
        $this->authenticationManager->expects($this->once())->method('authenticate')->with($token)->will($this->returnValue($response));
        $this->responseEvent->expects($this->once())->method('setResponse')->with($response);
        $this->request->headers->add(array('X-WSSE'=>'UsernameToken Username="someuser", PasswordDigest="somedigest", Nonce="somenonce", Created="2010-12-12 20:00:00"'));

        $listener = new Listener($this->securityContext, $this->authenticationManager, 'someproviderkey', $this->authenticationEntryPoint);
        $listener->handle($this->responseEvent);
    }
}