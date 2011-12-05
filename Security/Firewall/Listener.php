<?php

namespace Escape\WSSEAuthenticationBundle\Security\Firewall;

use Escape\WSSEAuthenticationBundle\Security\Authentication\Token\Token;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class Listener implements ListenerInterface
{
	protected $securityContext;
	protected $authenticationManager;

	public function __construct(SecurityContextInterface $securityContext, AuthenticationManagerInterface $authenticationManager)
	{
		$this->securityContext = $securityContext;
		$this->authenticationManager = $authenticationManager;
	}

	public function handle(GetResponseEvent $event)
	{
		$request = $event->getRequest();

		if($request->headers->has('X-WSSE'))
		{
			$wsseRegex = '/UsernameToken Username="([^"]+)", PasswordDigest="([^"]+)", Nonce="([^"]+)", Created="([^"]+)"/';

			if(preg_match($wsseRegex, $request->headers->get('X-WSSE'), $matches))
			{
				$token = new Token();
				$token->setUser($matches[1]);
				$token->digest = $matches[2];
				$token->nonce = $matches[3];
				$token->created = $matches[4];

				try
				{
					$returnValue = $this->authenticationManager->authenticate($token);

					if($returnValue instanceof TokenInterface)
						return $this->securityContext->setToken($returnValue);
					else if($returnValue instanceof Response)
						return $event->setResponse($returnValue);
				}
				catch(AuthenticationException $e)
				{
					//you might want to log something here
				}
			}

			$response = new Response();
			$response->setStatusCode(403);//forbidden
			$event->setResponse($response);
		}
		else
		{
			$response = new Response();
			$response->setStatusCode(401);//unauthorized
			$event->setResponse($response);

			return;
		}
	}
}