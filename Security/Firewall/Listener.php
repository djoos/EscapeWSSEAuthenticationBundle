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

use UnexpectedValueException;

class Listener implements ListenerInterface
{
	protected $securityContext;
	protected $authenticationManager;
    private $wsseHeader;

	public function __construct(SecurityContextInterface $securityContext, AuthenticationManagerInterface $authenticationManager)
	{
		$this->securityContext = $securityContext;
		$this->authenticationManager = $authenticationManager;
	}

    /**
     * The method returns value of a bit header by the key
     *
     * @param $key
     * @return mixed
     * @throws \UnexpectedValueException
     */
    private function parseValue($key)
    {
        if(!preg_match('/' . $key . '="([^"]+)"/', $this->wsseHeader, $matches)) {
            throw new UnexpectedValueException('The string was not found');
        }

        return $matches[1];
    }

    /**
     * The method parses X-WSSE header. If Username, PasswordDigest, Nonce and Created are exists then it returns value of them.
     * Otherwise the method returns false.
     *
     * @return array|bool
     */
    private function parseHeader()
    {
        $result = array();
        try {
            $result['Username'] = $this->parseValue('Username');
            $result['PasswordDigest'] = $this->parseValue('PasswordDigest');
            $result['Nonce'] = $this->parseValue('Nonce');
            $result['Created'] = $this->parseValue('Created');
        } catch (UnexpectedValueException $e) {
            return false;
        }

        return $result;
    }

	public function handle(GetResponseEvent $event)
	{
		$request = $event->getRequest();

		if($request->headers->has('X-WSSE'))
		{
            $this->wsseHeader = $request->headers->get('X-WSSE');
            $wsseHeaderInfo = $this->parseHeader();

			if($wsseHeaderInfo !== false)
			{
				$token = new Token();
				$token->setUser($wsseHeaderInfo['Username']);
				$token->digest = $wsseHeaderInfo['PasswordDigest'];
				$token->nonce = $wsseHeaderInfo['Nonce'];
				$token->created = $wsseHeaderInfo['Created'];

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
