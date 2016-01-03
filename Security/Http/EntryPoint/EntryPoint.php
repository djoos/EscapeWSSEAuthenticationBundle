<?php

namespace Escape\WSSEAuthenticationBundle\Security\Http\EntryPoint;

use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Log\LoggerInterface;

class EntryPoint implements AuthenticationEntryPointInterface
{
    private $logger;
    private $realm;
    private $profile;

    public function __construct(
        LoggerInterface $logger = null,
        $realm = null,
        $profile = "UsernameToken"
    )
    {
        $this->logger = $logger;
        $this->realm = $realm;
        $this->profile = $profile;
    }

    public function start(Request $request, AuthenticationException $ae = null)
    {
        if($this->logger !== null)
        {
            if($ae instanceof AuthenticationException)
            {
                $this->logger->warning($ae->getMessage());
            }
        }

        $response = new Response();

        $response->headers->set(
            'WWW-Authenticate',
            sprintf(
                'WSSE realm="%s", profile="%s"',
                $this->realm,
                $this->profile
            )
        );

        $response->setStatusCode(401);//unauthorized

        return $response;
    }

    public function getRealm()
    {
        return $this->realm;
    }

    public function getProfile()
    {
        return $this->profile;
    }
}
