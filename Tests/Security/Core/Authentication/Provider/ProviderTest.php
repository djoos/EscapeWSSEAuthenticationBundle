<?php

namespace Escape\WSSEAuthenticationBundle\Tests\Security\Core\Authentication\Provider;

use Escape\WSSEAuthenticationBundle\Security\Core\Authentication\Provider\Provider;
use Escape\WSSEAuthenticationBundle\Security\Core\Authentication\Token\Token;

use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Finder\Finder;
use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use Symfony\Component\Security\Core\Encoder\MessageDigestPasswordEncoder;

class ProviderTestSimple extends Provider
{
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

    private static $nonceDir;

    //the setUpBeforeClass() template method is called before the first test of the test case class is run
    public static function setUpBeforeClass()
    {
        parent::setUpBeforeClass();

        self::$nonceDir = __DIR__.'/../../../../nonceDir/';

        $fs = new Filesystem();

        if(!$fs->exists(self::$nonceDir))
        {
            $fs->mkdir(self::$nonceDir);
        }
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
        $provider = new Provider($this->userProvider, $this->encoder);
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
     * @expectedException \Symfony\Component\Security\Core\Exception\CredentialsExpiredException
     * @param $digest
     * @param $nonce
     * @param $created
     * @param $secret
     */
    public function validateDigestExpireTime()
    {
        $provider = new ProviderTestSimple($this->userProvider, $this->encoder);
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
        $provider = new ProviderTestSimple($this->userProvider, $this->encoder);
        $result = $provider->validateDigest($this->user, $digest, $nonce, $created, $secret);
        $this->assertEquals($expected, $result);
    }

    public function providerValidateDigest()
    {
        $time = date('Y-m-d H:i:s');
        $digest = base64_encode(sha1(base64_decode(base64_encode('test')).$time.'test', true));

        return array(
            array($digest, base64_encode('test'), $time, 'test', true),
            array($digest, base64_encode('test'), $time, 'test1', false),
            array($digest, base64_encode('test2'), $time, 'test', false),
            array($digest. '9', base64_encode('test'), $time, 'test', false)
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
        $provider = new ProviderTestSimple($this->userProvider, $this->encoder, self::$nonceDir);
        $result = $provider->validateDigest($this->user, $digest, $nonce, $created, $secret);
        $this->assertEquals($expected, $result);

        $this->assertFileExists(self::$nonceDir.$nonce);

        try {
          $result = $provider->validateDigest($this->user, $digest, $nonce, $created, $secret);
          $this->fail('NonceExpiredException expected');
        } catch (NonceExpiredException $e) {
          unlink(self::$nonceDir.$nonce);
        }


/*
        //expire timestamp after specified lifetime
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

        return $digest === $expected;
*/
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
        $provider = new ProviderTestSimple($this->userProvider, $this->encoder, self::$nonceDir);
        file_put_contents(self::$nonceDir.$nonce, time()-123);

        $provider->validateDigest($this->user, $digest, $nonce, $created, $secret);

        unlink(self::$nonceDir.$nonce);
    }

    /**
     * @test
     * @dataProvider providerValidateDigest
     */
    public function validateDigestWithoutFuturnTokenCheck($digest, $nonce, $created, $secret, $expected)
    {
        $provider = new ProviderTestSimple($this->userProvider, $this->encoder, self::$nonceDir, 300, false);
        $created = date('Y-m-d H:i:s', time() + 1); // put time to future

        $provider->validateDigest($this->user, $digest, $nonce, $created, $secret);
        unlink(self::$nonceDir.$nonce);
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
        $provider = new ProviderTestSimple($this->userProvider, $this->encoder);
        $provider->authenticate(new Token());

/*
        $user = $this->userProvider->loadUserByUsername($token->getUsername());

        if($user && $this->validateDigest($user, $token->digest, $token->nonce, $token->created, $user->getPassword()))
        {
            $authenticatedToken = new Token($user->getRoles());
            $authenticatedToken->setUser($user);
            $authenticatedToken->setAuthenticated(true);

            return $authenticatedToken;
        }

        throw new AuthenticationException('WSSE authentication failed.');
 */
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
        $this->user->expects($this->once())->method('getPassword')->will($this->returnValue('test'));
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
                'test',
                $time,
                'test'
            ),
            ""
        );

        $token = new Token();
        $token->setAttribute('digest', $digest);
        $token->setAttribute('nonce', base64_encode('test'));
        $token->setAttribute('created', $time);

        $provider = new ProviderTestSimple($this->userProvider, $this->encoder);
        $result = $provider->authenticate($token);

        $this->assertEquals($expected, $result);
    }
}