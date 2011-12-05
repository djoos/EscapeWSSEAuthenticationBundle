<?php

namespace Escape\WSSEAuthenticationBundle\Security\Authentication\Provider;

use Escape\WSSEAuthenticationBundle\Security\Authentication\Token\UserToken;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class Provider implements AuthenticationProviderInterface
{
	private $userProvider;
	private $cacheDir;

	public function __construct(UserProviderInterface $userProvider, $cacheDir)
	{
		$this->userProvider = $userProvider;
		$this->cacheDir = $cacheDir;
	}

	public function authenticate(TokenInterface $token)
	{
		$user = $this->userProvider->loadUserByUsername($token->getUsername());

		if($user && $this->validateDigest($token->digest, $token->nonce, $token->created, $user->getPassword()))
		{
			$authenticatedToken = new UserToken($user->getRoles());
			$authenticatedToken->setUser($user);

			return $authenticatedToken;
		}

		throw new AuthenticationException('The WSSE authentication failed.');
	}

	protected function validateDigest($digest, $nonce, $created, $secret)
	{
		//expire timestamp after 5 minutes
		if(time() - strtotime($created) > 300)
			return false;

//		//validate nonce is unique within 5 minutes
//		if(file_exists($this->cacheDir.'/'.$nonce) && file_get_contents($this->cacheDir.'/'.$nonce) + 300 < time())
//			throw new NonceExpiredException('Previously used nonce detected');

//@todo store nonces
//		file_put_contents($this->cacheDir.'/'.$nonce, time());

		//validate secret
		//$expected = base64_encode(sha1(base64_decode($nonce.$created.$secret)/* .$created.$secret */, true));
		$expected = base64_encode(sha1(base64_decode($nonce).$created.$secret, true));

		return $digest === $expected;
	}

	public function supports(TokenInterface $token)
	{
		return $token instanceof UserToken;
	}
}