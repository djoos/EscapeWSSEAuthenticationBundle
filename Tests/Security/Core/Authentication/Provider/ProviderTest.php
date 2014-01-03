<?php

namespace Escape\WSSEAuthenticationBundle\Tests\Security\Core\Authentication\Provider;

use Escape\WSSEAuthenticationBundle\Security\Core\Authentication\Provider\Provider;
use Escape\WSSEAuthenticationBundle\Security\Core\Authentication\Token\Token;

use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Finder\Finder;
use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use Symfony\Component\Security\Core\Encoder\MessageDigestPasswordEncoder;

use Doctrine\Common\Cache\PhpFileCache;

class CustomProvider extends Provider
{
    //open up scope for protected Provider's validateDigest-method
    public function validateDigest($user, $digest, $nonce, $created, $secret)
    {
        return parent::validateDigest($user, $digest, $nonce, $created, $secret);
    }
}

class ProviderTest extends \PHPUnit_Framework_TestCase
{
    private $userProvider;
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
        $provider = new Provider($this->userProvider, $this->encoder, $this->nonceCache);
        $this->assertEquals($expected, $provider->supports($token));
    }

    //data provider
    public function providerSupports()
    {
        return array(
            array(new Token(), true),
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
        $provider = new CustomProvider($this->userProvider, $this->encoder, $this->nonceCache);
        $provider->validateDigest(null, null, null, date('r', (time() - 86400)), null);
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
        $provider = new CustomProvider($this->userProvider, $this->encoder, $this->nonceCache);
        $result = $provider->validateDigest($this->user, $digest, $nonce, $created, $secret);
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
    public function validateDigestWithNonceDir($digest, $nonce, $created, $secret, $expected)
    {
        $provider = new CustomProvider($this->userProvider, $this->encoder, $this->nonceCache);
        $result = $provider->validateDigest($this->user, $digest, $nonce, $created, $secret);
        $this->assertEquals($expected, $result);

        $this->assertTrue($this->nonceCache->contains($nonce));

        try
        {
          $result = $provider->validateDigest($this->user, $digest, $nonce, $created, $secret);
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
    public function validateDigestWithNonceDirExpectedException($digest, $nonce, $created, $secret, $expected)
    {
        $provider = new CustomProvider($this->userProvider, $this->encoder, $this->nonceCache);

        $this->nonceCache->save($nonce, time() - 123, 0);

        $provider->validateDigest($this->user, $digest, $nonce, $created, $secret);

        $this->nonceCache->delete($nonce);
    }

    //data provider
    public function providerValidateDigest()
    {
        $time = date('Y-m-d H:i:s');

        $encoder = new MessageDigestPasswordEncoder('sha1', true, 1);

        $digest = $encoder->encodePassword(
            sprintf(
                '%s%s%s',
                'somenonce',
                $time,
                'somesecret'
            ),
            ""
        );

        $digest_slash = $encoder->encodePassword(
            sprintf(
                '%s%s%s',
                's/o/m/e/n/o/n/c/e',
                $time,
                'somesecret'
            ),
            ""
        );

        return array(
            array($digest, base64_encode('somenonce'), $time, 'somesecret', true),
            array($digest, base64_encode('somenonce'), $time, 'somewrongsecret', false),
            array($digest, base64_encode('somewrongnonce'), $time, 'somesecret', false),
            array($digest. '9', base64_encode('somenonce'), $time, 'somesecret', false),
            array($digest_slash, base64_encode('s/o/m/e/n/o/n/c/e'), $time, 'somesecret', true)
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
        $provider = new CustomProvider($this->userProvider, $this->encoder, $this->nonceCache);
        $provider->authenticate(new Token());
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
        $this->user->expects($this->once())->method('getRoles')->will($this->returnValue(array()));
        $this->userProvider->expects($this->once())->method('loadUserByUsername')->will($this->returnValue($this->user));

        $expected = new Token();
        $expected->setUser($this->user);
        $expected->setAuthenticated(true);

        $time = date('Y-m-d H:i:s');

        $encoder = new MessageDigestPasswordEncoder('sha1', true, 1);
        $digest = $encoder->encodePassword(
            sprintf(
                '%s%s%s',
                'somenonce',
                $time,
                'somesecret'
            ),
            ""
        );

        $token = new Token();
        $token->setAttribute('digest', $digest);
        $token->setAttribute('nonce', base64_encode('somenonce'));
        $token->setAttribute('created', $time);

        $provider = new CustomProvider($this->userProvider, $this->encoder, $this->nonceCache);
        $result = $provider->authenticate($token);

        $this->assertEquals($expected, $result);
    }
}
