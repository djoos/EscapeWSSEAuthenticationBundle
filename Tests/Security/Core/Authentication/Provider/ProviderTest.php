<?php

namespace Escape\WSSEAuthenticationBundle\Tests\Security\Core\Authentication\Provider;

use Escape\WSSEAuthenticationBundle\Security\Core\Authentication\Provider\Provider;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken as Token;

use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Finder\Finder;
use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use Symfony\Component\Security\Core\Encoder\MessageDigestPasswordEncoder;

use Doctrine\Common\Cache\PhpFileCache;

class CustomProvider extends Provider
{
    //open up scope for protected Provider's validateDigest-method
    public function validateDigest($digest, $nonce, $created, $secret, $salt)
    {
        return parent::validateDigest($digest, $nonce, $created, $secret, $salt);
    }
}

class ProviderTest extends \PHPUnit_Framework_TestCase
{
    private $userProvider;
    private $providerKey;
    private $encoder;
    private $user;
    private $nonceCache;

    private static $nonceDir;

    //the setUpBeforeClass() template method is called before the first test of the test case class is run
    public static function setUpBeforeClass()
    {
        parent::setUpBeforeClass();

        self::$nonceDir = __DIR__.'/../../../../nonces/';
    }

    //the tearDownAfterClass() template method is called after the last test of the test case class is run
    public static function tearDownAfterClass()
    {
        parent::tearDownAfterClass();

        $fs = new Filesystem();

        //cleanup
        if($fs->exists(self::$nonceDir))
        {
            $fs->remove(self::$nonceDir);
        }
    }

    private function clearDir()
    {
        $fs = new Filesystem();

        $finder = new Finder();

        $finder->files()->in(self::$nonceDir);

        foreach($finder as $file)
        {
            $fs->remove($file->getRealPath());
        }
    }

    protected function setUp()
    {
        $this->userProvider = $this->getMock('Symfony\Component\Security\Core\User\UserProviderInterface');
        $this->providerKey = 'someproviderkey';
        $this->encoder = new MessageDigestPasswordEncoder('sha1', true, 1);
        $this->nonceCache = new PhpFileCache(self::$nonceDir);
        $this->user = $this->getMock('Symfony\Component\Security\Core\User\UserInterface');

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
        $provider = new Provider($this->userProvider, 'someproviderkey', $this->encoder, $this->nonceCache);
        $this->assertEquals($expected, $provider->supports($token));
    }

    //data provider
    public function providerSupports()
    {
        return array(
            array(new Token('someuser', 'somepassword', 'someproviderkey'), true),
            array($this->getMock('Symfony\Component\Security\Core\Authentication\Token\TokenInterface'), false)
        );
    }

    /**
     * @test
     * @expectedException \Symfony\Component\Security\Core\Exception\CredentialsExpiredException
     * @param $digest
     * @param $nonce
     * @param $created
     * @param $secret
     */
    public function validateDigestExpireTime()
    {
        $provider = new CustomProvider($this->userProvider, $this->providerKey, $this->encoder, $this->nonceCache);
        $provider->validateDigest(null, null, date(DATE_ISO8601, (time() - 86400)), null, null);
    }

    /**
     * @test
     * @dataProvider providerValidateDigest
     * @param $digest
     * @param $nonce
     * @param $created
     * @param $secret
     */
    public function validateDigestWithoutNonceDir($digest, $nonce, $created, $secret, $salt, $expected)
    {
        $provider = new CustomProvider($this->userProvider, $this->providerKey, $this->encoder, $this->nonceCache);
        $result = $provider->validateDigest($digest, $nonce, $created, $secret, $salt);
        $this->assertEquals($expected, $result);
    }

    /**
     * @test
     * @dataProvider providerValidateDigest
     * @param $digest
     * @param $nonce
     * @param $created
     * @param $secret
     */
    public function validateDigestWithNonceDir($digest, $nonce, $created, $secret, $salt, $expected)
    {
        $provider = new CustomProvider($this->userProvider, $this->providerKey, $this->encoder, $this->nonceCache);
        $result = $provider->validateDigest($digest, $nonce, $created, $secret, $salt);
        $this->assertEquals($expected, $result);

        $this->assertTrue($this->nonceCache->contains($nonce));

        try
        {
          $result = $provider->validateDigest($digest, $nonce, $created, $secret, $salt);
          $this->fail('NonceExpiredException expected');
        }
        catch(NonceExpiredException $e)
        {
          $this->nonceCache->delete($nonce);
        }
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
    public function validateDigestWithNonceDirExpectedException($digest, $nonce, $created, $secret, $salt, $expected)
    {
        $provider = new CustomProvider($this->userProvider, $this->providerKey, $this->encoder, $this->nonceCache);

        $this->nonceCache->save($nonce, time() - 123, 0);

        $provider->validateDigest($digest, $nonce, $created, $salt, $secret, $salt);

        $this->nonceCache->delete($nonce);
    }

    //data provider
    public function providerValidateDigest()
    {
        $time = date(DATE_ISO8601);

        $encoder = new MessageDigestPasswordEncoder('sha1', true, 1);

        $digest = $encoder->encodePassword(
            sprintf(
                '%s%s%s',
                'somenonce',
                $time,
                'somesecret'
            ),
            'somesalt'
        );

        $digest_slash = $encoder->encodePassword(
            sprintf(
                '%s%s%s',
                's/o/m/e/n/o/n/c/e',
                $time,
                'somesecret'
            ),
            'somesalt'
        );

        return array(
            array($digest, base64_encode('somenonce'), $time, 'somesecret', 'somesalt', true),
            array($digest, base64_encode('somenonce'), $time, 'somewrongsecret', 'somesalt', false),
            array($digest, base64_encode('somenonce'), $time, 'somesecret', 'somewrongsalt', false),
            array($digest, base64_encode('somewrongnonce'), $time, 'somesecret', 'somesalt', false),
            array($digest. '9', base64_encode('somenonce'), $time, 'somesecret', 'somesalt', false),
            array($digest_slash, base64_encode('s/o/m/e/n/o/n/c/e'), $time, 'somesecret', 'somesalt', true)
        );
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
        $provider = new CustomProvider($this->userProvider, $this->providerKey, $this->encoder, $this->nonceCache);
        $provider->authenticate(new Token($this->user, '', $this->providerKey));
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
        $this->user->expects($this->once())->method('getPassword')->will($this->returnValue('somesecret'));
        $this->user->expects($this->once())->method('getSalt')->will($this->returnValue('somesalt'));
        $this->user->expects($this->once())->method('getRoles')->will($this->returnValue(array()));
        $this->userProvider->expects($this->once())->method('loadUserByUsername')->will($this->returnValue($this->user));

        $encoder = new MessageDigestPasswordEncoder('sha1', true, 1);
        $time = date(DATE_ISO8601);

        $digest = $encoder->encodePassword(
            sprintf(
                '%s%s%s',
                'somenonce',
                $time,
                'somesecret'
            ),
            'somesalt'
        );

        $expected = new Token($this->user, $digest, $this->providerKey);

        $time = date(DATE_ISO8601);

        $digest = $encoder->encodePassword(
            sprintf(
                '%s%s%s',
                'somenonce',
                $time,
                'somesecret'
            ),
            'somesalt'
        );

        $token = new Token($this->user, $digest, $this->providerKey);
        $token->setAttribute('nonce', base64_encode('somenonce'));
        $token->setAttribute('created', $time);

        $provider = new CustomProvider($this->userProvider, $this->providerKey, $this->encoder, $this->nonceCache);
        $result = $provider->authenticate($token);

        $this->assertEquals($expected, $result);
    }
}
