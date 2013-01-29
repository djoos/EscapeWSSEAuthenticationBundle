<?php

namespace Mayflower\WSSEAuthenticationBundle\Tests\Security\Core\Authentication\Token;

use Mayflower\WSSEAuthenticationBundle\Security\Core\Authentication\Token\Token;

class TokenTest extends \PHPUnit_Framework_TestCase
{
	/**
	 * @test
	 */
	public function getCredentials()
	{
		$token = new Token();
		$this->assertEquals('', $token->getCredentials());
	}
}