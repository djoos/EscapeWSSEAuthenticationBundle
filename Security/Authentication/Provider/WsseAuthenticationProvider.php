<?php

namespace Escape\WSSEAuthenticationBundle\Security\Authentication\Provider;

use Escape\WSSEAuthenticationBundle\Security\Authentication\Token\WsseToken;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserCheckerInterface;

class WsseAuthenticationProvider implements AuthenticationProviderInterface
{
    protected $providerKey;
    protected $userProvider;
    protected $userChecker;
    protected $createIfNotExists;
	protected $nonceDir;
	protected $lifetime;

	public function __construct($providerKey, $nonceDir = null, $lifetime = 300, UserProviderInterface $userProvider = null, UserCheckerInterface $userChecker = null, $createIfNotExists = false)
	{
		if (null !== $userProvider && null === $userChecker) {
			throw new \InvalidArgumentException('$userChecker cannot be null, if $userProvider is not null.');
		}

		if ($createIfNotExists && !$userProvider instanceof UserManagerInterface) {
			throw new \InvalidArgumentException('The $userProvider must implement UserManagerInterface if $createIfNotExists is true.');
		}

		$this->providerKey = $providerKey;
		$this->userProvider = $userProvider;
		$this->userChecker = $userChecker;
		$this->createIfNotExists = $createIfNotExists;
		$this->nonceDir = $nonceDir;
		$this->lifetime = $lifetime;
	}
	public function authenticate(TokenInterface $token)
	{
		$user = $this->userProvider->loadUserByUsername($token->getUsername());
		if($user && $this->validateDigest($token->digest, $token->nonce, $token->created, $user->getPassword()))
		{
			$authenticatedToken = new Token($user->getRoles());
			$authenticatedToken->setUser($user);
            $authenticatedToken->setAuthenticated(true);

			return $authenticatedToken;
		}

		throw new AuthenticationException('WSSE authentication failed.');
	}

	protected function validateDigest($digest, $nonce, $created, $secret)
	{
		//expire timestamp after specified lifetime
		if(time() - strtotime($created) > $this->lifetime)
		{
			return false;
		}

		if($this->nonceDir)
		{
			//validate nonce is unique within specified lifetime
			if(file_exists($this->nonceDir.'/'.$nonce) && file_get_contents($this->nonceDir.'/'.$nonce) + $this->lifetime < time())
			{
				throw new NonceExpiredException('Previously used nonce detected');
			}

			file_put_contents($this->nonceDir.'/'.$nonce, time());
		}

		//validate secret
		$expected = base64_encode(sha1(base64_decode($nonce).$created.$secret, true));
		return $digest === $expected;
	}

	public function supports(TokenInterface $token)
	{
		return $token instanceof WsseToken;
	}
}
