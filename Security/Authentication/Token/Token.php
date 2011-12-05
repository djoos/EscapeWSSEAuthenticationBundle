<?php

namespace Escape\WSSEAuthenticationBundle\Security\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class Token extends AbstractToken
{
	public $created;
	public $digest;
	public $nonce;

	public function getCredentials()
	{
		return '';
	}
}