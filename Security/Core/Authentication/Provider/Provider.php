<?php

namespace Escape\WSSEAuthenticationBundle\Security\Core\Authentication\Provider;

use Escape\WSSEAuthenticationBundle\Security\Core\Authentication\Token\Token;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CredentialsExpiredException;
use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;

use Doctrine\Common\Cache\Cache;

class Provider implements AuthenticationProviderInterface
{
    private $userProvider;
    private $encoder;
    private $nonceCache;
    private $lifetime;

    /**
     * Constructor.
     *
     * @param UserProviderInterface    $userProvider              An UserProviderInterface instance
     * @param PasswordEncoderInterface $encoder                   A PasswordEncoderInterface instance
     * @param Cache                    $nonceCache                The nonce cache
     * @param int                      $lifetime                  The lifetime
    */
    public function __construct(UserProviderInterface $userProvider, PasswordEncoderInterface $encoder, Cache $nonceCache, $lifetime=300)
    {
        $this->userProvider = $userProvider;
        $this->encoder = $encoder;
        $this->nonceCache = $nonceCache;
        $this->lifetime = $lifetime;
    }

    public function authenticate(TokenInterface $token)
    {
        $user = $this->userProvider->loadUserByUsername($token->getUsername());

        if(
            $user &&
            $this->validateDigest(
                $token->getAttribute('digest'),
                $token->getAttribute('nonce'),
                $token->getAttribute('created'),
                $this->getSecret($user),
                $this->getSalt()
           )
        )
        {
            $authenticatedToken = new Token($user->getRoles());
            $authenticatedToken->setUser($user);
            $authenticatedToken->setAuthenticated(true);

            return $authenticatedToken;
        }

        throw new AuthenticationException('WSSE authentication failed.');
    }

    protected function getSecret(UserInterface $user)
    {
        return $user->getPassword();
    }

    protected function getSalt()
    {
        return "";
    }

    protected function validateDigest($digest, $nonce, $created, $secret, $salt)
    {
        //check whether timestamp is not in the future
        if($this->isTokenFromFuture($created))
        {
            throw new CredentialsExpiredException('Future token detected.');
        }

        //expire timestamp after specified lifetime
        if(time() - strtotime($created) > $this->lifetime)
        {
            throw new CredentialsExpiredException('Token has expired.');
        }

        //validate that nonce is unique within specified lifetime
        //if it is not, this could be a replay attack
        if($this->nonceCache->contains($nonce))
        {
            throw new NonceExpiredException('Previously used nonce detected.');
        }

        $this->nonceCache->save($nonce, time(), $this->lifetime);

        //validate secret
        $expected = $this->encoder->encodePassword(
            sprintf(
                '%s%s%s',
                base64_decode($nonce),
                $created,
                $secret
            ),
            $salt
        );

        return $digest === $expected;
    }

    protected function isTokenFromFuture($created)
    {
        return strtotime($created) > time();
    }

    public function getUserProvider()
    {
        return $this->userProvider;
    }

    public function getEncoder()
    {
        return $this->encoder;
    }

    public function getNonceCache()
    {
        return $this->nonceCache;
    }

    public function getLifetime()
    {
        return $this->lifetime;
    }

    public function supports(TokenInterface $token)
    {
        return $token instanceof Token;
    }
}