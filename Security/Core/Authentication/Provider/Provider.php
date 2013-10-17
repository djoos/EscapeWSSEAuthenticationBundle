<?php

namespace Escape\WSSEAuthenticationBundle\Security\Core\Authentication\Provider;

use Escape\WSSEAuthenticationBundle\Security\Core\Authentication\Token\Token;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CredentialsExpiredException;
use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class Provider implements AuthenticationProviderInterface
{
    private $userProvider;
    private $nonceDir;
    private $lifetime;

    public function __construct(UserProviderInterface $userProvider, $nonceDir=null, $lifetime=300)
    {
        $this->userProvider = $userProvider;
        $this->nonceDir = $nonceDir;
        $this->lifetime = $lifetime;
    }

    public function getLifetime()
    {
        return $this->lifetime;
    }

    public function getNonceDir()
    {
        return $this->nonceDir;
    }

    public function getUserProvider()
    {
        return $this->userProvider;
    }

    public function authenticate(TokenInterface $token)
    {
        $user = $this->getUserProvider()->loadUserByUsername($token->getUsername());

        if ($user && $this->validateDigest($token->getAttribute('digest'), $token->getAttribute('nonce'), $token->getAttribute('created'), $this->getUserSecret($user))) {
            $authenticatedToken = new Token($user->getRoles());
            $authenticatedToken->setUser($user);
            $authenticatedToken->setAuthenticated(true);

            return $authenticatedToken;
        }

        throw new AuthenticationException('WSSE authentication failed.');
    }

    public function supports(TokenInterface $token)
    {
        return $token instanceof Token;
    }

    protected function getUserSecret($user)
    {
        return $user->getPassword();
    }

    protected function validateDigest($digest, $nonce, $created, $secret)
    {
        //expire timestamp after specified lifetime
        if(time() - strtotime($created) > $this->getLifetime())
        {
            throw new CredentialsExpiredException('Token has expired.');
        }

        if($this->nonceDir)
        {
            //validate nonce is unique within specified lifetime
            if(file_exists($this->getNonceDir().'/'.$nonce) && file_get_contents($this->getNonceDir().'/'.$nonce) + $this->getLifetime() > time())
            {
                throw new NonceExpiredException('Previously used nonce detected.');
            }

            file_put_contents($this->getNonceDir().'/'.$nonce, time());
        }

        //validate secret
        $expected = base64_encode(sha1(base64_decode($nonce).$created.$secret, true));

        return $digest === $expected;
    }
}
