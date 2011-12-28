<?php

namespace Escape\WSSEAuthenticationBundle\Tests\Security\Firewall;

use Escape\WSSEAuthenticationBundle\Security\Firewall\Listener;
use Symfony\Component\HttpFoundation\Response;
use Escape\WSSEAuthenticationBundle\Security\Authentication\Token\Token;

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

    protected function setUp()
    {
        $this->responseEvent = $this->getMockBuilder('\Symfony\Component\HttpKernel\Event\GetResponseEvent')->disableOriginalConstructor()->getMock();
        $this->request = $this->getMockForAbstractClass('Symfony\Component\HttpFoundation\Request');
        $this->responseEvent->expects($this->once())->method('getRequest')->will($this->returnValue($this->request));
        $this->securityContext = $this->getMock('\Symfony\Component\Security\Core\SecurityContextInterface');
        $this->authenticationManager = $this->getMock('\Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface');
    }

    /**
     * @test
     */
    public function handleUnauthorized()
    {
        $listener = new Listener($this->securityContext, $this->authenticationManager);
        $response = new Response();
        $response->setStatusCode(401);//unauthorized
        $this->responseEvent->expects($this->once())->method('setResponse')->with($response);
        $result = $listener->handle($this->responseEvent);
    }

    /**
     * @test
     */
    public function handleForbidden()
    {
        $listener = new Listener($this->securityContext, $this->authenticationManager);
        $this->request->headers->add(array('X-WSSE'=>'temp'));
        $response = new Response();
        $response->setStatusCode(403);//unauthorized
        $this->responseEvent->expects($this->once())->method('setResponse')->with($response);
        $result = $listener->handle($this->responseEvent);
    }

    /**
     * @test
     */
    public function handleReturnToken()
    {
        $token = new Token();
        $token->setUser('admin');
        $token->digest = 'admin';
        $token->nonce = 'admin';
        $token->created = '2010-12-12 20:00:00';
        $tokenMock2 = $this->getMock('Symfony\Component\Security\Core\Authentication\Token\TokenInterface');
        $this->authenticationManager->expects($this->once())->method('authenticate')->with($token)->will($this->returnValue($tokenMock2));
        $this->securityContext->expects($this->once())->method('setToken')->with($tokenMock2);
        $this->request->headers->add(array('X-WSSE'=>'UsernameToken Username="admin", PasswordDigest="admin", Nonce="admin", Created="2010-12-12 20:00:00"'));
        $listener = new Listener($this->securityContext, $this->authenticationManager);
        $listener->handle($this->responseEvent);
    }

    /**
     * @test
     */
    public function handleReturnResponse()
    {
        $token = new Token();
        $token->setUser('admin');
        $token->digest = 'admin';
        $token->nonce = 'admin';
        $token->created = '2010-12-12 20:00:00';
        $response = new Response();
        $this->authenticationManager->expects($this->once())->method('authenticate')->with($token)->will($this->returnValue($response));
        $this->responseEvent->expects($this->once())->method('setResponse')->with($response);
        $this->request->headers->add(array('X-WSSE'=>'UsernameToken Username="admin", PasswordDigest="admin", Nonce="admin", Created="2010-12-12 20:00:00"'));
        $listener = new Listener($this->securityContext, $this->authenticationManager);
        $listener->handle($this->responseEvent);
    }

}
