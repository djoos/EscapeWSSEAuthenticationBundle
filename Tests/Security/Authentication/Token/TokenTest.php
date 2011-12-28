<?php
/**
 * @author Dmitry Petrov <dmitry.petrov@opensoftdev.ru>
 */
namespace Escape\WSSEAuthenticationBundle\Tests\Security\Authentication\Token;

use Escape\WSSEAuthenticationBundle\Security\Authentication\Token\Token;

/**
 * @author Dmitry Petrov <dmitry.petrov@opensoftdev.ru>
 */
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

    public function testIssetPublicVariables()
    {
        $token = new Token();
        $this->assertClassHasAttribute('created', get_class($token));
        $this->assertClassHasAttribute('digest', get_class($token));
        $this->assertClassHasAttribute('nonce', get_class($token));
    }
}
