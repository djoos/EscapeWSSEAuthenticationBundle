<?php

namespace Escape\WSSEAuthenticationBundle\Security\Core\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class Token extends AbstractToken
{
	public function getCredentials()
	{
		return '';
	}
}