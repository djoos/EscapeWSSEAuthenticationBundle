<?php

namespace Escape\WSSEAuthenticationBundle\Security\Firewall;


use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Escape\WSSEAuthenticationBundle\Security\Authentication\Token\WsseToken;
use UnexpectedValueException;

class WsseListener implements ListenerInterface
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
        if(!preg_match('/'.$key.'="([^"]+)"/', $this->wsseHeader, $matches))
        {
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

        try
        {
            $result['Username'] = $this->parseValue('Username');
            $result['PasswordDigest'] = $this->parseValue('PasswordDigest');
            $result['Nonce'] = $this->parseValue('Nonce');
            $result['Created'] = $this->parseValue('Created');
        }
        catch(UnexpectedValueException $e)
        {
            return false;
        }

        return $result;
    }

	public function handle(GetResponseEvent $event)
	{
		$request = $event->getRequest();

        if ($request->headers->has('x-wsse')) {

            $wsseRegex = '/UsernameToken Username="([^"]+)", PasswordDigest="([^"]+)", Nonce="([^"]+)", Created="([^"]+)"/';

            if (preg_match($wsseRegex, $request->headers->get('x-wsse'), $matches)) {

                $token = new WsseToken();
                $token->setUser($matches[1]);

                $token->digest   = $matches[2];
                $token->nonce    = $matches[3];
                $token->created  = $matches[4];
				var_dump($token);exit;
                try {
                    $returnValue = $this->authenticationManager->authenticate($token);
                    if ($returnValue instanceof TokenInterface) {
                        return $this->securityContext->setToken($returnValue);
                    } else if ($returnValue instanceof Response) {
                        return $event->setResponse($returnValue);
                    }
                } catch (AuthenticationException $authException) {
			        $response = new Response();
			        $response->setStatusCode(401, $authException ? $authException->getMessage() : null);
        			$event->setResponse($response);
        			return;
                }
            }
        }

        $response = new Response();
        $response->setStatusCode(403);
        $event->setResponse($response);
	}
}
