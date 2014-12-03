<?php

namespace Escape\WSSEAuthenticationBundle\Security\Http\Firewall;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken as Token;

use UnexpectedValueException;

class Listener implements ListenerInterface
{
    /**
     * @var string WSSE header
     */
    private $wsseHeader;

    /**
     * @var SecurityContextInterface
     */
    protected $securityContext;

    /**
     * @var AuthenticationManagerInterface
     */
    protected $authenticationManager;

    /**
     * @var string Uniquely identifies the secured area
     */
    protected $providerKey;

    /**
     * @var AuthenticationEntryPointInterface
     */
    protected $authenticationEntryPoint;

    public function __construct(
        SecurityContextInterface $securityContext,
        AuthenticationManagerInterface $authenticationManager,
        $providerKey,
        AuthenticationEntryPointInterface $authenticationEntryPoint
    )
    {
        $this->securityContext = $securityContext;
        $this->authenticationManager = $authenticationManager;
        $this->providerKey = $providerKey;
        $this->authenticationEntryPoint = $authenticationEntryPoint;
    }

    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();

        //find out if the current request contains any information by which the user might be authenticated
        if(!$request->headers->has('X-WSSE'))
        {
            return;
        }

        $ae_message = null;
        $this->wsseHeader = $request->headers->get('X-WSSE');
        $wsseHeaderInfo = $this->parseHeader();

        if($wsseHeaderInfo !== false)
        {
            $token = new Token(
                $wsseHeaderInfo['Username'],
                $wsseHeaderInfo['PasswordDigest'],
                $this->providerKey
            );

            $token->setAttribute('nonce', $wsseHeaderInfo['Nonce']);
            $token->setAttribute('created', $wsseHeaderInfo['Created']);

            try
            {
                $returnValue = $this->authenticationManager->authenticate($token);

                if($returnValue instanceof TokenInterface)
                {
                    return $this->securityContext->setToken($returnValue);
                }
                else if($returnValue instanceof Response)
                {
                    return $event->setResponse($returnValue);
                }
            }
            catch(AuthenticationException $ae)
            {
                $event->setResponse($this->authenticationEntryPoint->start($request, $ae));
            }
        }
    }

    /**
     * This method returns the value of a bit header by the key
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
     * This method parses the X-WSSE header
     * 
     * If Username, PasswordDigest, Nonce and Created exist then it returns their value,
     * otherwise the method returns false.
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
}