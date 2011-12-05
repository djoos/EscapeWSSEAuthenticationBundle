<?php

namespace Escape\WSSEAuthenticationBundle\Security\Authentication\Provider;

use Escape\WSSEAuthenticationBundle\Security\Authentication\Token\Token;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class Provider implements AuthenticationProviderInterface
{
	private $userProvider;
	private $cacheDir;
	private $lifetime;

	public function __construct(UserProviderInterface $userProvider, $cacheDir=null, $lifetime=null)
	{
		$this->userProvider = $userProvider;
		$this->cacheDir = $cacheDir;
		$this->lifetime = $lifetime;
	}

	public function authenticate(TokenInterface $token)
	{
		$user = $this->userProvider->loadUserByUsername($token->getUsername());

		if($user && $this->validateDigest($token->digest, $token->nonce, $token->created, $user->getPassword()))
		{
			$authenticatedToken = new Token($user->getRoles());
			$authenticatedToken->setUser($user);

			return $authenticatedToken;
		}

		throw new AuthenticationException('WSSE authentication failed.');
	}

	protected function validateDigest($digest, $nonce, $created, $secret)
	{
		//expire timestamp after specified lifetime
		if(time() - strtotime($created) > $this->lifetime)
			return false;

		if($this->cacheDir)
		{
			//validate nonce is unique within 5 minutes
			if(file_exists($this->cacheDir.'/'.$nonce) && file_get_contents($this->cacheDir.'/'.$nonce) + $this->lifetime < time())
				throw new NonceExpiredException('Previously used nonce detected');

			file_put_contents($this->cacheDir.'/'.$nonce, time());
		}

		//validate secret
		$expected = base64_encode(sha1(base64_decode($nonce.$created.$secret), true));

		return $digest === $expected;
	}

	public function supports(TokenInterface $token)
	{
		return $token instanceof Token;
	}
}