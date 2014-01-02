<?php

namespace Escape\WSSEAuthenticationBundle\Security\Core\Authentication\Provider;

use Escape\WSSEAuthenticationBundle\Security\Core\Authentication\Token\Token;

use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CredentialsExpiredException;
use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class Provider implements AuthenticationProviderInterface
{
    private $userProvider;
    private $encoder;
    private $nonceDir;
    private $lifetime;
    private $futureTokenCheck;

    /**
     * Constructor.
     *
     * @param UserProviderInterface    $userProvider              An UserProviderInterface instance
     * @param PasswordEncoderInterface $encoder                   A PasswordEncoderInterface instance
     * @param string                   $nonceDir                  The nonce dir
     * @param int                      $lifetime                  The lifetime
     * @param boolean                  $futurnTokenCheck          Check whether timestamp is not in the future
    */
    public function __construct(UserProviderInterface $userProvider, PasswordEncoderInterface $encoder, $nonceDir=null, $lifetime=300, $futureTokenCheck=true)
    {
        $this->userProvider = $userProvider;
        $this->encoder = $encoder;
        $this->nonceDir = $nonceDir;
        $this->lifetime = $lifetime;
        $this->futureTokenCheck = $futureTokenCheck;
    }

    public function authenticate(TokenInterface $token)
    {
        $user = $this->userProvider->loadUserByUsername($token->getUsername());

        if($user && $this->validateDigest($user, $token->getAttribute('digest'), $token->getAttribute('nonce'), $token->getAttribute('created'), $this->getSecret($user)))
        {
            $authenticatedToken = new Token($user->getRoles());
            $authenticatedToken->setUser($user);
            $authenticatedToken->setAuthenticated(true);

            return $authenticatedToken;
        }

        throw new AuthenticationException('WSSE authentication failed.');
    }

    protected function getSecret($user)
    {
        return $user->getPassword();
    } 

    protected function validateDigest($user, $digest, $nonce, $created, $secret)
    {
        //check whether timestamp is not in the future
        if($this->futureTokenCheck && strtotime($created) > time())
        {
            throw new CredentialsExpiredException('Future token detected.');
        }

        //expire timestamp after specified lifetime
        if(time() - strtotime($created) > $this->lifetime)
        {
            throw new CredentialsExpiredException('Token has expired.');
        }

        if($this->nonceDir)
        {
            $fs = new Filesystem();

            if(!$fs->exists($this->nonceDir))
            {
                $fs->mkdir($this->nonceDir);
            }

            //validate that nonce is unique within specified lifetime
            //if it is not, this could be a replay attack
            if(
                file_exists($this->nonceDir.DIRECTORY_SEPARATOR.$nonce) &&
                file_get_contents($this->nonceDir.DIRECTORY_SEPARATOR.$nonce) + $this->lifetime > time()
            )
            {
                throw new NonceExpiredException('Previously used nonce detected.');
            }

            file_put_contents($this->nonceDir.'/'.$nonce, time());
        }

        //validate secret
        $expected = $this->encoder->encodePassword(
            sprintf(
                '%s%s%s',
                base64_decode($nonce),
                $created,
                $secret
            ),
            ""
        );

        return $digest === $expected;
    }

    public function supports(TokenInterface $token)
    {
        return $token instanceof Token;
    }
}