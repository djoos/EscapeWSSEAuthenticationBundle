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

	public function authenticate(TokenInterface $token)
	{
		$user = $this->userProvider->loadUserByUsername($token->getUsername());

		if($user && $this->validateDigest($token->getAttribute('digest'), $token->getAttribute('nonce'), $token->getAttribute('created'), $user->getPassword()))
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
			throw new CredentialsExpiredException('Token has expired.');
		}

		if($this->nonceDir)
		{
			//validate nonce is unique within specified lifetime
			if(file_exists($this->nonceDir.'/'.$nonce) && file_get_contents($this->nonceDir.'/'.$nonce) + $this->lifetime < time())
			{
				throw new NonceExpiredException('Previously used nonce detected.');
			}

			file_put_contents($this->nonceDir.'/'.$nonce, time());
		}

		//validate secret
		$expected = base64_encode(sha1(base64_decode($nonce).$created.$secret, true));

		return $digest === $expected;
	}

	public function supports(TokenInterface $token)
	{
		return $token instanceof Token;
	}
}