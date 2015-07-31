<?php

namespace Escape\WSSEAuthenticationBundle\Security\Core\Authentication\Provider;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CredentialsExpiredException;
use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken as Token;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Util\StringUtils;

use Doctrine\Common\Cache\Cache;

class Provider implements AuthenticationProviderInterface
{
    private $userProvider;
    private $providerKey;
    private $encoder;
    private $nonceCache;
    private $lifetime;
    private $dateFormat;

    /**
     * Constructor.
     *
     * @param UserProviderInterface    $userProvider              An UserProviderInterface instance
     * @param PasswordEncoderInterface $encoder                   A PasswordEncoderInterface instance
     * @param Cache                    $nonceCache                The nonce cache
     * @param int                      $lifetime                  The lifetime
     * @param string                   $dateFormat                The date format
    */
    public function __construct(
        UserProviderInterface $userProvider,
        $providerKey,
        PasswordEncoderInterface $encoder,
        Cache $nonceCache,
        $lifetime=300,
        $dateFormat='/^([\+-]?\d{4}(?!\d{2}\b))((-?)((0[1-9]|1[0-2])(\3([12]\d|0[1-9]|3[01]))?|W([0-4]\d|5[0-2])(-?[1-7])?|(00[1-9]|0[1-9]\d|[12]\d{2}|3([0-5]\d|6[1-6])))([T\s]((([01]\d|2[0-3])((:?)[0-5]\d)?|24\:?00)([\.,]\d+(?!:))?)?(\17[0-5]\d([\.,]\d+)?)?([zZ]|([\+-])([01]\d|2[0-3]):?([0-5]\d)?)?)?)?$/'
    )
    {
        if(empty($providerKey))
        {
            throw new \InvalidArgumentException('$providerKey must not be empty.');
        }

        $this->userProvider = $userProvider;
        $this->providerKey = $providerKey;
        $this->encoder = $encoder;
        $this->nonceCache = $nonceCache;
        $this->lifetime = $lifetime;
        $this->dateFormat = $dateFormat;
    }

    public function authenticate(TokenInterface $token)
    {
        $user = $this->userProvider->loadUserByUsername($token->getUsername());

        if(
            $user &&
            $this->validateDigest(
                $token->getCredentials(),
                $token->getAttribute('nonce'),
                $token->getAttribute('created'),
                $this->getSecret($user),
                $this->getSalt($user)
           )
        )
        {
            $authenticatedToken = new Token(
                $user,
                $token->getCredentials(),
                $this->providerKey,
                $user->getRoles()
            );

            return $authenticatedToken;
        }

        throw new AuthenticationException('WSSE authentication failed.');
    }

    protected function getSecret(UserInterface $user)
    {
        return $user->getPassword();
    }

    protected function getSalt(UserInterface $user)
    {
        return $user->getSalt();
    }

    protected function validateDigest($digest, $nonce, $created, $secret, $salt)
    {
        //check whether timestamp is formatted correctly
        if(!$this->isFormattedCorrectly($created))
        {
            throw new BadCredentialsException('Incorrectly formatted "created" in token.');
        }

        //check whether timestamp is not in the future
        if($this->isTokenFromFuture($created))
        {
            throw new BadCredentialsException('Future token detected.');
        }

        //expire timestamp after specified lifetime
        if(strtotime($this->getCurrentTime()) - strtotime($created) > $this->lifetime)
        {
            throw new CredentialsExpiredException('Token has expired.');
        }

        //validate that nonce is unique within specified lifetime
        //if it is not, this could be a replay attack
        if($this->nonceCache->contains($nonce))
        {
            throw new NonceExpiredException('Previously used nonce detected.');
        }

        $this->nonceCache->save($nonce, strtotime($this->getCurrentTime()), $this->lifetime);

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

        return StringUtils::equals($expected, $digest);
    }

    protected function getCurrentTime()
    {
        return gmdate(DATE_ISO8601);
    }

    protected function isTokenFromFuture($created)
    {
        return strtotime($created) > strtotime($this->getCurrentTime());
    }

    protected function isFormattedCorrectly($created)
    {
        return preg_match($this->getDateFormat(), $created);
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

    public function getDateFormat()
    {
        return $this->dateFormat;
    }

    public function supports(TokenInterface $token)
    {
        return $token instanceof Token && $this->providerKey === $token->getProviderKey();
    }
}
