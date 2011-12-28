<?php
/**
 * @author Dmitry Petrov <dmitry.petrov@opensoftdev.ru>
 */
namespace Escape\WSSEAuthenticationBundle\Tests\Security\Authentication\Provider;

use Escape\WSSEAuthenticationBundle\Security\Authentication\Provider\Provider;
use Escape\WSSEAuthenticationBundle\Security\Authentication\Token\Token;

class ProviderTestSimple extends Provider
{
    public function validateDigest($digest, $nonce, $created, $secret)
    {
        return parent::validateDigest($digest, $nonce, $created, $secret);
    }
}

/**
 * @author Dmitry Petrov <dmitry.petrov@opensoftdev.ru>
 */
class ProviderTest extends \PHPUnit_Framework_TestCase
{
    private $userProvider;

    private static $nonceDir;

    public static function setUpBeforeClass()
    {
        parent::setUpBeforeClass();
        static::$nonceDir = __DIR__ . '/../../../nonceDir/';
    }

    private function clearDir()
    {
        $handle = opendir(static::$nonceDir);
        while ($tmp = readdir($handle)) {
            if($tmp != '..' && $tmp != '.' && $tmp != '') {
                unlink(static::$nonceDir . $tmp);
            }
        }


    }
    protected function setUp()
    {
        $this->userProvider = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $this->clearDir();
    }

    /**
     * @test
     * @dataProvider providerSupports
     * @param $token
     * @param $expected
     */
    public function supports($token, $expected)
    {
        $provider = new Provider($this->userProvider);
        $this->assertEquals($expected, $provider->supports($token));
    }

    public function providerSupports()
    {
        return array(
            array(new Token(), true),
            array($this->getMock('Symfony\Component\Security\Core\Authentication\Token\TokenInterface'), false)
        );
    }

    /**
     * @test
     *
     * @param $digest
     * @param $nonce
     * @param $created
     * @param $secret
     */
    public function validateDigestExpireTime()
    {
        $provider = new ProviderTestSimple($this->userProvider);
        $result = $provider->validateDigest(null, null, '2000-10-10 12:00:00', null);
        $this->assertFalse($result);
    }

    /**
     * @test
     * @dataProvider providerValidateDigest
     * @param $digest
     * @param $nonce
     * @param $created
     * @param $secret
     */
    public function validateDigestWithoutNonceDir($digest, $nonce, $created, $secret, $expected)
    {
        $provider = new ProviderTestSimple($this->userProvider);
        $result = $provider->validateDigest($digest, $nonce, $created, $secret);
        $this->assertEquals($expected, $result);
    }

    public function providerValidateDigest()
    {
        $time = date('Y-m-d H:i:s');
        $digest = base64_encode(sha1(base64_decode(base64_encode('test')).$time.'test', true));
        return array(
            array($digest, base64_encode('test'), $time, 'test', true),
            array($digest, base64_encode('test'), $time, 'test1', false),
            array($digest, base64_encode('test'), $time+4, 'test', false),
            array($digest, base64_encode('test2'), $time, 'test', false),
            array($digest. '9', base64_encode('test'), $time, 'test', false),
        );
    }

    /**
     * @test
     * @dataProvider providerValidateDigest
     * @param $digest
     * @param $nonce
     * @param $created
     * @param $secret
     */
    public function validateDigestWithNonceDir($digest, $nonce, $created, $secret, $expected)
    {
        $provider = new ProviderTestSimple($this->userProvider, __DIR__ . '/../../../nonceDir');
        $result = $provider->validateDigest($digest, $nonce, $created, $secret);
        $this->assertEquals($expected, $result);

        $this->assertFileExists(static::$nonceDir . $nonce);

        $result = $provider->validateDigest($digest, $nonce, $created, $secret);
        $this->assertEquals($expected, $result);

        unlink(static::$nonceDir . $nonce);
        /*//expire timestamp after specified lifetime
        if(time() - strtotime($created) > $this->lifetime)
            return false;

        if($this->nonceDir)
        {
            //validate nonce is unique within specified lifetime
            if(file_exists($this->nonceDir.'/'.$nonce) && file_get_contents($this->nonceDir.'/'.$nonce) + $this->lifetime < time())
                throw new NonceExpiredException('Previously used nonce detected');

            file_put_contents($this->nonceDir.'/'.$nonce, time());
        }

        //validate secret
        $expected = base64_encode(sha1(base64_decode($nonce).$created.$secret), true);

        return $digest === $expected;*/
    }

    /**
     * @test
     * @dataProvider providerValidateDigest
     * @expectedException \Symfony\Component\Security\Core\Exception\NonceExpiredException
     * @param $digest
     * @param $nonce
     * @param $created
     * @param $secret
     */
    public function validateDigestWithNonceDirExpectedException($digest, $nonce, $created, $secret, $expected)
    {
        $provider = new ProviderTestSimple($this->userProvider, __DIR__ . '/../../../nonceDir');
        file_put_contents(static::$nonceDir . $nonce, time() - 60000);

        $provider->validateDigest($digest, $nonce, $created, $secret);

        unlink(static::$nonceDir . $nonce);
    }

    /**
     * @test
     *
     * @depends validateDigestWithNonceDirExpectedException
     * @depends validateDigestWithNonceDir
     * @depends validateDigestWithoutNonceDir
     * @depends validateDigestExpireTime
     * @expectedException \Symfony\Component\Security\Core\Exception\AuthenticationException
     */
    public function authenticateExpectedException()
    {
        $provider = new ProviderTestSimple($this->userProvider);
        $provider->authenticate(new Token());
        /*$user = $this->userProvider->loadUserByUsername($token->getUsername());

        if($user && $this->validateDigest($token->digest, $token->nonce, $token->created, $user->getPassword()))
        {
            $authenticatedToken = new Token($user->getRoles());
            $authenticatedToken->setUser($user);
            $authenticatedToken->setAuthenticated(true);

            return $authenticatedToken;
        }

        throw new AuthenticationException('WSSE authentication failed.');*/
    }

    /**
     * @test
     * @depends validateDigestWithNonceDirExpectedException
     * @depends validateDigestWithNonceDir
     * @depends validateDigestWithoutNonceDir
     * @depends validateDigestExpireTime
     */
    public function authenticate()
    {
        $user = $this->getMock('Symfony\Component\Security\Core\User\UserInterface');
        $user->expects($this->once())->method('getPassword')->will($this->returnValue('test'));
        $user->expects($this->once())->method('getRoles')->will($this->returnValue(array()));
        $this->userProvider->expects($this->once())->method('loadUserByUsername')->will($this->returnValue($user));

        $expected = new Token();
        $expected->setUser($user);
        $expected->setAuthenticated(true);


        $time = date('Y-m-d H:i:s');
        $digest = base64_encode(sha1(base64_decode(base64_encode('test')).$time.'test', true));
        //$digest, base64_encode('test'), $time, 'test', true),
        $token = new Token();
        $token->digest = $digest;
        $token->nonce = base64_encode('test');
        $token->created = $time;

        $provider = new ProviderTestSimple($this->userProvider);
        $result = $provider->authenticate($token);

        $this->assertEquals($expected, $result);
    }
}
