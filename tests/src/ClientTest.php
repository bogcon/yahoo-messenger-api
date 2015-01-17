<?php
/**
 * Unit test for BogCon\YahooMessengerApi\Client class.
 *
 * @author    Bogdan Constantinescu <bog_con@yahoo.com>
 * @copyright Copyright (c) 2013-2015 Bogdan Constantinescu
 * @link      GitHub https://github.com/bogcon/yahoo-messenger-api
 * @license   New BSD License (http://opensource.org/licenses/BSD-3-Clause);
 *            see LICENSE.txt file that came along with this package.
 */
namespace BogCon\YahooMessengerApi\Tests;

use BogCon\YahooMessengerApi\Client;

/**
 * @covers BogCon\YahooMessengerApi\Client
 */
class ClientTest extends \PHPUnit_Framework_TestCase
{
    /**
     * Test username.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @expectedExceptionMessage    Invalid param username. Must be a string.
     * @covers \BogCon\YahooMessengerApi\Client::__construct
     */
    public function testConstructorParamUsername1()
    {
        $objYM = new Client(array(), '', '', '');
    }
    
    
    
    /**
     * Test username.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @expectedExceptionMessage    Invalid param username. Must contain at most one @.
     * @covers \BogCon\YahooMessengerApi\Client::__construct
     */
    public function testConstructorParamUsername2()
    {
        $objYM = new Client('john@doe@yahoo.com', '', '', '');
    }
    
    
    
    /**
     * Test username.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @expectedExceptionMessage    Invalid param username. ID must match [a-z0-9_.+] and must have at most 32 chars.
     * @covers \BogCon\YahooMessengerApi\Client::__construct
     */
    public function testConstructorParamUsername3()
    {
        $strName = '';
        for ($intI = 0; $intI < 33; $intI++) {
            $strName .= 'a';
        }
        $objYM = new Client($strName, '', '', '');
    }
    
    
    
    /**
     * Test username.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @expectedExceptionMessage    Invalid param username. ID must match [a-z0-9_.+] and must have at most 32 chars.
     * @covers \BogCon\YahooMessengerApi\Client::__construct
     */
    public function testConstructorParamUsername4()
    {
        $objYM = new Client('#johndoe', '', '', '');
    }
    
    
    
    /**
     * Test username.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @expectedExceptionMessage    Invalid param username. DNS must match [a-z0-9_.+] and must have at most 64 chars.
     * @covers \BogCon\YahooMessengerApi\Client::__construct
     */
    public function testConstructorParamUsername5()
    {
        $strDns = '';
        for ($intI = 0; $intI < 62; $intI++) {
            $strDns .= 'a';
        }
        $objYM = new Client('johndoe@' . $strDns . '.com', '', '', '');
    }
    
    
    
    /**
     * Test password.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @expectedExceptionMessage    Invalid param password.
     * @covers \BogCon\YahooMessengerApi\Client::__construct
     */
    public function testConstructorParamPassword1()
    {
        $objYM = new Client('johndoe', array(), '', '');
    }
    
    
    
    /**
     * Test password.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @expectedExceptionMessage    Invalid param password.
     * @covers \BogCon\YahooMessengerApi\Client::__construct
     */
    public function testConstructorParamPassword2()
    {
        $strPwd = '';
        for ($intI = 0; $intI < 33; $intI++) {
            $strPwd .= 'a';
        }
        $objYM = new Client('johndoe', $strPwd, '', '');
    }
    
    
    
    /**
     * Test app key param.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @expectedExceptionMessage    Invalid param app key.
     * @covers \BogCon\YahooMessengerApi\Client::__construct
     */
    public function testConstructorParamAppKey1()
    {
        $objYM = new Client('johndoe', 'pass123', array(), '');
    }
    
    
    
    /**
     * Test app key param.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @expectedExceptionMessage    Invalid param app key.
     * @covers \BogCon\YahooMessengerApi\Client::__construct
     */
    public function testConstructorParamAppKey2()
    {
        $objYM = new Client('johndoe', 'pass123', '', '');
    }
    
    
    
    /**
     * Test app secret param.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @expectedExceptionMessage    Invalid param app secret.
     * @covers \BogCon\YahooMessengerApi\Client::__construct
     */
    public function testConstructorParamAppSecret1()
    {
        $objYM = new Client('johndoe', 'pass123', 'appKey', array());
    }
    
    
    
    /**
     * Test app secret param.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @expectedExceptionMessage    Invalid param app secret.
     * @covers \BogCon\YahooMessengerApi\Client::__construct
     */
    public function testConstructorParamAppSecret2()
    {
        $objYM = new Client('johndoe', 'pass123', 'appKey', '');
    }
    
    
    
    /**
     * Test everything goes ok with some valid params, test default values.
     * @requires extension curl
     * @requires extension mbstring
     * @covers \BogCon\YahooMessengerApi\Client::__construct
     * @covers \BogCon\YahooMessengerApi\Client::hasAccessToken
     * @covers \BogCon\YahooMessengerApi\Client::hasRequestToken
     * @covers \BogCon\YahooMessengerApi\Client::hasSession
     * @covers \BogCon\YahooMessengerApi\Client::isTokenRenewed
     */
    public function testConstructorWorksFine()
    {
        $objYM = new Client('johndoe', 'abcdefgppppp', 'testAppKey', 'testAppSecret');
        $this->assertFalse($objYM->hasRequestToken());
        $this->assertFalse($objYM->hasAccessToken());
        $this->assertFalse($objYM->hasSession());
        $this->assertFalse($objYM->isTokenRenewed());
    }
    
    
    
    /**
     * Test setter/getter method for tokens.
     * @covers \BogCon\YahooMessengerApi\Client::setTokens
     * @covers \BogCon\YahooMessengerApi\Client::getTokens
     * @covers \BogCon\YahooMessengerApi\Client::hasAccessToken
     * @covers \BogCon\YahooMessengerApi\Client::hasRequestToken
     */
    public function testSetGetHasTokens()
    {
        $arrTokens = array(
            'request' => 'someTestRequestToken',
            'access' => array(
                'oauth_token' => 'sometestOAuthToken',
                'oauth_token_secret' => 'someTestOAuthTokenSecret',
                'oauth_expires_in' => '3600',
                'oauth_session_handle' => 'someTestOAuthSessionHandle',
                'oauth_authorization_expires_in' => '770477963',
                'xoauth_yahoo_guid' => 'someTestXOAuthYahooGuid'
            ),
        );
        $objYM = new Client('das1sdas', 'dasda123sdas', 'appKey', 'appSecret');
        $this->assertSame(array(), $objYM->getTokens());
        $objYM->setTokens($arrTokens);
        $this->assertSame($arrTokens, $objYM->getTokens());
        $this->assertTrue($objYM->hasAccessToken());
        $this->assertTrue($objYM->hasRequestToken());
        
        $objYM->setTokens(array());
        $this->assertFalse($objYM->hasAccessToken());
        $this->assertFalse($objYM->hasRequestToken());
    }
    
    
    
    /**
     * Test setter/getter method for session.
     * @covers \BogCon\YahooMessengerApi\Client::setSession
     * @covers \BogCon\YahooMessengerApi\Client::getSession
     * @covers \BogCon\YahooMessengerApi\Client::hasSession
     */
    public function testSetGetHasSession()
    {
        $arrSession = array(
            'sessionId' => 'someTestSessionId',
            'primaryLoginId' => 'someLoginId',
            'displayInfo' => array(
                'avatarPreference' => 0,
            ),
            'server' => 'rcore3.messenger.yahooapis.com',
            'notifyServer' => 'rproxy3.messenger.yahooapis.com',
            'constants' => array(
                'presenceSubscriptionsMaxPerRequest' => 500,
            ),
        );

        $objYM = new Client('das1sdas', 'dasda123sdas', 'appKey', 'appSecret');
        $this->assertSame(array(), $objYM->getSession());
        
        $objYM->setSession($arrSession);
        $this->assertSame($arrSession, $objYM->getSession());
        $this->assertTrue($objYM->hasSession());
        
        $objYM->setSession(array());
        $this->assertFalse($objYM->hasSession());
    }
    
    
    
    /**
     * Test setter/getter method for renewed token flag.
     * @covers \BogCon\YahooMessengerApi\Client::setTokenRenewed
     * @covers \BogCon\YahooMessengerApi\Client::isTokenRenewed
     */
    public function testSetIsTokenRenewed()
    {
        $objYM = new Client('vxc123ads', 'das_+DAS', 'appKey', 'appSecret');
        $this->assertFalse($objYM->isTokenRenewed());
        $objYM->setTokenRenewed(true);
        $this->assertTrue($objYM->isTokenRenewed());
        $objYM->setTokenRenewed(false);
        $this->assertFalse(false, $objYM->isTokenRenewed());
        $objYM->setTokenRenewed(0);
        $this->assertFalse($objYM->isTokenRenewed());
        $objYM->setTokenRenewed('trueeee');
        $this->assertTrue($objYM->isTokenRenewed());
    }
    
    
    
    /**
     * Test exception is thrown when request token is not received from api call.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @covers \BogCon\YahooMessengerApi\Client::getRequestToken
     * @covers \BogCon\YahooMessengerApi\Client::hasRequestToken
     */
    public function testGetRequestTokenIsThrowingException()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        $objMock->expects($this->once())
                ->method('makeApiCall')
                ->will($this->returnValue('aaaaaaa'));
        $objMock->getRequestToken();
    }
    
    
    
    /**
     * Test method works properly.
     * @covers \BogCon\YahooMessengerApi\Client::getRequestToken
     * @covers \BogCon\YahooMessengerApi\Client::hasRequestToken
     */
    public function testGetRequestTokenWorksFine()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        $objMock->expects($this->once()) // first time make api call
                ->method('makeApiCall')
                ->will($this->returnValue('RequestToken=cadscas1231234wre'));
        $this->assertEquals('cadscas1231234wre', $objMock->getRequestToken());
        $this->assertTrue($objMock->hasRequestToken());
        
        $objMock->expects($this->never()) // second time retrieve directly
                ->method('makeApiCall');
        $this->assertEquals('cadscas1231234wre', $objMock->getRequestToken());
        
        $objMock->setTokens(array('request' => 'testRequestToken'));
        $objMock->expects($this->never()) // test no api call is made after request is set manually
                ->method('makeApiCall');
        $this->assertEquals('testRequestToken', $objMock->getRequestToken());
    }
    
    
    
    /**
     * Test exception is thrown when access token is not received from api call.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @covers \BogCon\YahooMessengerApi\Client::getAccessToken
     */
    public function testGetAccessTokenIsThrowingExceptionWhenNoAccessTokenIsReceived()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        $objMock->expects($this->once())
                ->method('makeApiCall')
                ->will($this->returnValue('aaaaaaa'));
        $objMock->setTokens(array('request' => 'testRequestToken'))
                ->getAccessToken();
    }
    
    
    
    /**
     * Test method is working properly when access token is received from api call.
     * @covers \BogCon\YahooMessengerApi\Client::getAccessToken
     * @covers \BogCon\YahooMessengerApi\Client::hasAccessToken
     * @covers \BogCon\YahooMessengerApi\Client::isTokenRenewed
     */
    public function testGetAccessTokenWorksFine()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        $objMock->expects($this->once()) // first time fetch access token from Yahoo API
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477963&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        $objMock->setTokens(array('request' => 'testRequestToken'));
        $accessToken = $objMock->getAccessToken();
        $this->assertNotEmpty($accessToken);
        $this->assertTrue($objMock->hasAccessToken());
        $this->assertTrue($objMock->isTokenRenewed()); // first call to isTokenRenewed should return true
        
        $objMock->expects($this->never()) // second time fetch internal
                ->method('makeApiCall');
        $this->assertSame($accessToken, $objMock->getAccessToken());
        $this->assertFalse($objMock->isTokenRenewed()); // second call to isTokenRenewed should return false
    }
    
    
    
    /**
     * Test method is working properly when access token is received from api call
     * and also request token was not previously set.
     * @covers \BogCon\YahooMessengerApi\Client::getAccessToken
     * @covers \BogCon\YahooMessengerApi\Client::hasAccessToken
     * @covers \BogCon\YahooMessengerApi\Client::isTokenRenewed
     */
    public function testGetAccessTokenWorksFine2()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        $objMock->expects($this->at(0)) // fetch request token call
                ->method('makeApiCall')
                ->will($this->returnValue('RequestToken=cadscas1231234wre'));
        $objMock->expects($this->at(1)) // fetch access token from Yahoo API
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477963&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        
        $accessToken = $objMock->getAccessToken();
        $this->assertNotEmpty($accessToken);
        $this->assertTrue($objMock->hasAccessToken());
        $this->assertTrue($objMock->isTokenRenewed()); // first call to isTokenRenewed should return true
        
        $objMock->expects($this->never()) // fetch access token internal
                ->method('makeApiCall');
        $this->assertSame($accessToken, $objMock->getAccessToken());
        $this->assertFalse($objMock->isTokenRenewed()); // second call to isTokenRenewed should return false
    }
    
    
    
    /**
     * Test access token renewal is throwing exception when no renewed access
     * token is received from api call.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @covers \BogCon\YahooMessengerApi\Client::getAccessToken
     */
    public function testGetAccessTokenForcedIsThrowingExceptionWhenNoNewAccessTokenIsReceived()
    {
        $objMock = $this->getMock('\BogCon\YahooMessengerApi\Client', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        $objMock->expects($this->once())
                ->method('makeApiCall')
                ->will($this->returnValue('dasdasdas'));
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_expires_in' => '3600',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                    'oauth_authorization_expires_in' => '770477963',
                    'xoauth_yahoo_guid' => 'someTestXOAuthYahooGuid'
                ),
            )
        );
        
        try {
            $objMock->getAccessToken(true);
        } catch (\BogCon\YahooMessengerApi\Exception $objEx) {
            if (false === mb_strpos($objEx->getMessage(), 'Could not fetch access token. Api response:')) {
                $this->fail('Not the expected exception. Received instead: ' . $objEx->getMessage());
            }
            throw $objEx;
        }
    }
    
    
    
    /**
     * Test access token renewal is working fine.
     * @covers \BogCon\YahooMessengerApi\Client::getAccessToken
     * @covers \BogCon\YahooMessengerApi\Client::isTokenRenewed
     * @covers \BogCon\YahooMessengerApi\Client::hasAccessToken
     * @covers \BogCon\YahooMessengerApi\Client::hasRequestToken
     */
    public function testGetAccessTokenForcedWorksFine()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        $objMock->expects($this->once())
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477970&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_expires_in' => '3600',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                    'oauth_authorization_expires_in' => '770477963',
                    'xoauth_yahoo_guid' => 'someTestXOAuthYahooGuid'
                ),
            )
        )->getAccessToken(true);
        
        $this->assertTrue($objMock->isTokenRenewed());
        $this->assertSame(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'testOAuthToken',
                    'oauth_token_secret' => 'testOAuthTokenSecret',
                    'oauth_expires_in' => '3600',
                    'oauth_session_handle' => 'testOAuthSessionHandle',
                    'oauth_authorization_expires_in' => '770477970',
                    'xoauth_yahoo_guid' => 'testXOAuthYahooGuid'
                ),
            ),
            $objMock->getTokens()
        );
        $this->assertTrue($objMock->hasAccessToken());
        $this->assertTrue($objMock->hasRequestToken());
        
        // test second call to getAccessToken() fetch internal, not from API
        $objMock->expects($this->never())
                ->method('makeApiCall');
        $this->assertSame(array(
            'oauth_token' => 'testOAuthToken',
            'oauth_token_secret' => 'testOAuthTokenSecret',
            'oauth_expires_in' => '3600',
            'oauth_session_handle' => 'testOAuthSessionHandle',
            'oauth_authorization_expires_in' => '770477970',
            'xoauth_yahoo_guid' => 'testXOAuthYahooGuid'
            
        ), $objMock->getAccessToken());
        // was renewed(taken from api) last call, now it is returned from internal field.
        $this->assertFalse($objMock->isTokenRenewed());
    }
    
    
    
    /**
     * Test login fails when http status code retreived from curl call is not 200.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @covers \BogCon\YahooMessengerApi\Client::logIn
     */
    public function testLogInThrowsExceptionWhenHttpStatusIsNot200()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        $objMock->expects($this->once())
                ->method('makeApiCall')
                ->will($this->returnValue('aaaa'));
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
    }
    
    
    
    /**
     * Test login fails when the response retreived from curl call is not valid json.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @covers \BogCon\YahooMessengerApi\Client::logIn
     */
    public function testLogInFailsWhenResponseIsNotValidJson()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        $intHttpStatusCode = 0;
        $objMock->expects($this->once())
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return 'aaaa';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn(100000, 'I am very busy'); // invalid status, should set the default one + status message
    }
    
    
    
    /**
     * Test login works ok.
     * @covers \BogCon\YahooMessengerApi\Client::logIn
     * @covers \BogCon\YahooMessengerApi\Client::getHeadersForCurlCall
     * @covers \BogCon\YahooMessengerApi\Client::getAuthorizationHeader
     */
    public function testLogInWorksFine()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        $intHttpStatusCode = 0;
        $arrSession = array(
            'sessionId' => 'someTestSessionId',
            'primaryLoginId' => 'someLoginId',
            'displayInfo' => array(
                'avatarPreference' => '0',
            ),
            'server' => 'rcore3.messenger.yahooapis.com',
            'notifyServer' => 'rproxy3.messenger.yahooapis.com',
            'constants' => array(
                'presenceSubscriptionsMaxPerRequest' => 500,
            ),
        );
        $objMock->expects($this->once())
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'displayInfo' => array(
                                        'avatarPreference' => '0',
                                    ),
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                    'notifyServer' => 'rproxy3.messenger.yahooapis.com',
                                    'constants' => array(
                                        'presenceSubscriptionsMaxPerRequest' => 500,
                                    ),
                                )
                            );
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        $this->assertSame($arrSession, $objMock->getSession());
    }
    
    
    
    /**
     * Test logout works fine if previously not logged in; just do nothing
     * @covers \BogCon\YahooMessengerApi\Client::logOut
     */
    public function testLogOutWorksFineIfNotLoggedIn()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        $objMock->expects($this->never())
                ->method('makeApiCall')
                ->will($this->returnValue('dasdas'));
        $objMock->logOut();
    }
    
    
    
    /**
     * Test logout fails when http status code retreived from curl call is not 200.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @expectedExceptionMessage logout
     * @covers \BogCon\YahooMessengerApi\Client::logOut
     */
    public function testLogOutFailsWhenHttpStatusIsNot200()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        $objMock->expects($this->at(0)) // login call
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objMock->expects($this->at(1))
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 302;
                            return '';
                        }
                    )
                );
                    
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        try {
            $objMock->logOut();
        } catch (\BogCon\YahooMessengerApi\Exception $objEx) {
            if (false === strpos($objEx->getMessage(), 'Could not log out. Api response')) {
                $this->fail('Exception should have been thrown.');
            }
            throw new \BogCon\YahooMessengerApi\Exception('logout');
        }
    }
    
    
    
    /**
     * Test logout works fine if previously logged in.
     * @covers \BogCon\YahooMessengerApi\Client::logOut
     */
    public function testLogOutWorksFineIfLoggedIn()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        $intHttpStatusCode = 0;
        $objMock->expects($this->at(0))
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objMock->expects($this->at(1))
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->logOut();
    }
    
    
    
    /**
     * Test logout works fine if token expired.
     * @covers \BogCon\YahooMessengerApi\Client::logOut
     * @covers \BogCon\YahooMessengerApi\Client::isTokenRenewed
     */
    public function testLogOutWorksFineIfLoggedInAndTokenExpired()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        $intHttpStatusCode = 0;
        $objMock->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objMock->expects($this->at(1)) // stubbing for logout to get access token expired
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return 'oauth_problem="token_expired"';
                        }
                    )
                );
        $objMock->expects($this->at(2)) // stubbing for logout to renew access token
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477963&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        $objMock->expects($this->at(3)) // stubbing for logout to successfully logout
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->logOut();
        $this->assertTrue($objMock->isTokenRenewed());
    }
    
    
    
    /**
     * Test headers from HTTP response are parsed well.
     * @covers \BogCon\YahooMessengerApi\Client::getHeadersFromCurlResponse
     */
    public function testGetHeadersFromCurlResponse()
    {
        $objYM = new Client('johndoe', 'abcdefgppppp', 'appKey', 'appSecret');
        
        $class = new \ReflectionClass($objYM); // method is protected, use reflection to make it accessible
        $method = $class->getMethod('getHeadersFromCurlResponse');
        $method->setAccessible(true);
        
        $arrWithHeaders = array(
            'http_code' => 'HTTP/1.1 200 OK',
            'date' => 'Wed, 04 Sep 2013 08:48:31 GMT',
            'p3p' => 'policyref="http://info.yahoo.com/w3c/p3p.xml", CP="CAO DSP COR CUR ADM DEV TAI PSA PSD IVAi IVDi CONi TELo OTPi OUR DELi SAMi OTRi UNRi PUBi IND PHY ONL UNI PUR FIN COM NAV INT DEM CNT STA POL HEA PRE LOC GOV"',
            'cache-control' => 'public,must-revalidate',
            'x-yahoo-msgr-imageurl' => 'http://msgr.zenfs.com/msgrDisImg/KMU47EN7G7XKKZJRK3EFJZSABQ',
            'connection' => 'close',
            'content-type' => '',
        );
        
        $this->assertSame(
            $method->invokeArgs(
                $objYM,
                array(
                    'HTTP/1.1 200 OK' . "\r\n"
                  . 'Date: Wed, 04 Sep 2013 08:48:31 GMT' . "\r\n"
                  . 'P3P: policyref="http://info.yahoo.com/w3c/p3p.xml", CP="CAO DSP COR CUR ADM DEV TAI PSA PSD IVAi IVDi CONi TELo OTPi OUR DELi SAMi OTRi UNRi PUBi IND PHY ONL UNI PUR FIN COM NAV INT DEM CNT STA POL HEA PRE LOC GOV"' . "\r\n"
                  . 'cache-control: public,must-revalidate' . "\r\n"
                  . 'x-yahoo-msgr-imageurl: http://msgr.zenfs.com/msgrDisImg/KMU47EN7G7XKKZJRK3EFJZSABQ' . "\r\n"
                  . 'Connection: close' . "\r\n"
                  . 'Content-Type: ' . "\r\n" . "\r\n"
                  . 'bla bla some content'
                )
            ),
            $arrWithHeaders
        );
    }
    
    
    
    /**
     * Test user avatar retrieval works fine.
     * @covers \BogCon\YahooMessengerApi\Client::fetchCustomAvatar
     */
    public function testFetchCustomAvatarWorksFine()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        
        $objMock->expects($this->at(0)) // needed for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objMock->expects($this->at(1))
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return 'HTTP/1.1 200 OK' . "\r\n"
                                 . 'Date: Wed, 04 Sep 2013 08:40:43 GMT' . "\r\n"
                                 . 'P3P: policyref="http://info.yahoo.com/w3c/p3p.xml", CP="CAO DSP COR CUR ADM DEV TAI PSA PSD IVAi IVDi CONi TELo OTPi OUR DELi SAMi OTRi UNRi PUBi IND PHY ONL UNI PUR FIN COM NAV INT DEM CNT STA POL HEA PRE LOC GOV"' . "\r\n"
                                 . 'cache-control: public,must-revalidate' . "\r\n"
                                 . 'x-yahoo-msgr-imageurl: http://msgr.zenfs.com/msgrDisImg/KMU47EN7G7XKKZJRK3EFJZSABQ' . "\r\n"
                                 . 'Connection: close' . "\r\n"
                                 . 'Content-Type: ' . "\r\n" . "\r\n";
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        $url = $objMock->fetchCustomAvatar('yahooid');
        $this->assertSame('http://msgr.zenfs.com/msgrDisImg/KMU47EN7G7XKKZJRK3EFJZSABQ', $url);
    }
    
    
    
    /**
     * Test user avatar retrieval fails when http status code retreived from curl call is not 200.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @covers \BogCon\YahooMessengerApi\Client::fetchCustomAvatar
     */
    public function testFetchCustomAvatarThrowsExceptionWhenStatusIsNot200()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        
        $objMock->expects($this->at(0))  // needed for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'displayInfo' => array(
                                        'avatarPreference' => '0',
                                    ),
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                    'notifyServer' => 'rproxy3.messenger.yahooapis.com',
                                    'constants' => array(
                                        'presenceSubscriptionsMaxPerRequest' => 500,
                                    ),
                                )
                            );
                        }
                    )
                );
        $objMock->expects($this->at(1))
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return 'bla bla bla';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->fetchCustomAvatar('yahooid');
        $this->fail("Exception should have been thrown");
    }
    
    
    
    /**
     * Test user avatar retrieval fails when header with the avatar url is not set
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @covers \BogCon\YahooMessengerApi\Client::fetchCustomAvatar
     */
    public function testFetchCustomAvatarThrowsExceptionWhenNoAvatarIsReceived()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('ter34dgf', 'tert34gdh', 'appKey123', 'appSecret123')
        );
        
        $objMock->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objMock->expects($this->at(1))  // stubbing for fetchCustomAvatar
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return 'HTTP/1.1 200 OK' . "\r\n"
                                . 'Date: Wed, 04 Sep 2013 08:40:43 GMT' . "\r\n"
                                . 'P3P: policyref="http://info.yahoo.com/w3c/p3p.xml", CP="CAO DSP COR CUR ADM DEV TAI PSA PSD IVAi IVDi CONi TELo OTPi OUR DELi SAMi OTRi UNRi PUBi IND PHY ONL UNI PUR FIN COM NAV INT DEM CNT STA POL HEA PRE LOC GOV"' . "\r\n"
                                . 'cache-control: public,must-revalidate' . "\r\n"
                                . 'Connection: close' . "\r\n"
                                . 'Content-Type: ' . "\r\n" . "\r\n";
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->fetchCustomAvatar('yahooid');
        $this->fail("Exception should have been thrown");
    }
    
    
    
    /**
     * Test user avatar retrieval works fine token is expired.
     * @covers \BogCon\YahooMessengerApi\Client::fetchCustomAvatar
     * @covers \BogCon\YahooMessengerApi\Client::isTokenRenewed
     */
    public function testFetchCustomAvatarWorksFineIfTokenExpired()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('ter34dgf', 'tert34gdh', 'appKey123', 'appSecret123')
        );
        $intHttpStatusCode = 0;
        $objMock->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objMock->expects($this->at(1)) // stubbing for fetchCustomAvatar to get access token expired
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return 'oauth_problem="token_expired"';
                        }
                    )
                );
        $objMock->expects($this->at(2)) // stubbing for fetchCustomAvatar to renew access token
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477963&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        $objMock->expects($this->at(3)) // stubbing for fetchCustomAvatar to successfully fetchCustomAvatar
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return 'HTTP/1.1 200 OK' . "\r\n"
                                . 'Date: Wed, 04 Sep 2013 08:40:43 GMT' . "\r\n"
                                . 'P3P: policyref="http://info.yahoo.com/w3c/p3p.xml", CP="CAO DSP COR CUR ADM DEV TAI PSA PSD IVAi IVDi CONi TELo OTPi OUR DELi SAMi OTRi UNRi PUBi IND PHY ONL UNI PUR FIN COM NAV INT DEM CNT STA POL HEA PRE LOC GOV"' . "\r\n"
                                . 'cache-control: public,must-revalidate' . "\r\n"
                                . 'x-yahoo-msgr-imageurl: http://msgr.zenfs.com/msgrDisImg/KMU47EN7G7XKKZJRK3EFJZSABQ' . "\r\n"
                                . 'Connection: close' . "\r\n"
                                . 'Content-Type: ' . "\r\n" . "\r\n";
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        $url = $objMock->fetchCustomAvatar('yahooid');
        $this->assertSame('http://msgr.zenfs.com/msgrDisImg/KMU47EN7G7XKKZJRK3EFJZSABQ', $url);
        $this->assertTrue($objMock->isTokenRenewed());
    }
    
    
    
    /**
     * Test groups retrieval works fine.
     * @covers \BogCon\YahooMessengerApi\Client::fetchGroups
     */
    public function testFetchGroupsWorksFine()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('ter34dgf', 'tert34gdh', 'appKey123', 'appSecret123')
        );
        
        $objMock->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
                
        $objMock->expects($this->at(1))
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '{"groups":[{"group":{"name":"GroupX","uri":"rcore3.messenger.yahooapis.com\/v1\/group\/GroupX","contacts":[{"contact":{"id":"yahooid1","uri":"rcore3.messenger.yahooapis.com\/v1\/contact\/yahoo\/yahooid1","presence":{"presenceState":0},"clientCapabilities":[{"clientCapability":"richText"},{"clientCapability":"smiley"},{"clientCapability":"buzz"},{"clientCapability":"fileXfer"},{"clientCapability":"voice"},{"clientCapability":"interop"},{"clientCapability":"typing"}],"addressbook":{"id":"12","firstname":"Jonh","lastname":"Doe","lastModified":1376325172}}},{"contact":{"id":"yahooid2","uri":"rcore3.messenger.yahooapis.com\/v1\/contact\/yahoo\/yahooid2","presence":{"presenceState":-1},"clientCapabilities":[],"addressbook":{"id":"3","firstname":"Johnny","lastname":"Doe","lastModified":1192198013}}}]}}],"start":0,"total":1,"count":1}';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        
        $groups = $objMock->fetchGroups();
        $this->assertTrue(is_array($groups));
        $this->assertSame($groups, json_decode('{"groups":[{"group":{"name":"GroupX","uri":"rcore3.messenger.yahooapis.com\/v1\/group\/GroupX","contacts":[{"contact":{"id":"yahooid1","uri":"rcore3.messenger.yahooapis.com\/v1\/contact\/yahoo\/yahooid1","presence":{"presenceState":0},"clientCapabilities":[{"clientCapability":"richText"},{"clientCapability":"smiley"},{"clientCapability":"buzz"},{"clientCapability":"fileXfer"},{"clientCapability":"voice"},{"clientCapability":"interop"},{"clientCapability":"typing"}],"addressbook":{"id":"12","firstname":"Jonh","lastname":"Doe","lastModified":1376325172}}},{"contact":{"id":"yahooid2","uri":"rcore3.messenger.yahooapis.com\/v1\/contact\/yahoo\/yahooid2","presence":{"presenceState":-1},"clientCapabilities":[],"addressbook":{"id":"3","firstname":"Johnny","lastname":"Doe","lastModified":1192198013}}}]}}],"start":0,"total":1,"count":1}', true));
    }
    
    
    
    /**
     * Test groups retrieval fails when http status code retreived from curl call is not 200.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @covers \BogCon\YahooMessengerApi\Client::fetchGroups
     */
    public function testFetchGroupsThrowsExceptionWhenStatusIsNot200()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('ter34dgf', 'tert34gdh', 'appKey123', 'appSecret123')
        );
        
        $objMock->expects($this->at(0))  // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objMock->expects($this->at(1)) // stubbing for fetchGroups
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return '';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->fetchGroups();
        $this->fail("Exception should have been thrown");
    }
    
    
    
    /**
     * Test groups retrieval throws exception when bad json is retrieved in response.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @expectedExceptionMessage json
     * @covers \BogCon\YahooMessengerApi\Client::fetchGroups
     */
    public function testFetchGroupsThrowsExceptionWhenBadJson()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('ter34dgf', 'tert34gdh', 'appKey123', 'appSecret123')
        );
        
        $objMock->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
                
        $objMock->expects($this->at(1))
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '---bad---json---';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        
        try {
            $objMock->fetchGroups();
        } catch (\BogCon\YahooMessengerApi\Exception $objEx) {
            if (false === strpos($objEx->getMessage(), 'Json error code')) {
                $this->fail("Exception should have been thrown");
            }
            throw new \BogCon\YahooMessengerApi\Exception('json');
        }
    }
    
    
    
    /**
     * Test groups retrieval throws exception when trying to access directly, without previously logging in.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @expectedExceptionMessage You have to be logged in in order to perform this action.
     * @covers \BogCon\YahooMessengerApi\Client::fetchGroups
     */
    public function testFetchGroupsThrowsExceptionWhenNoPreviouslyLoggedIn()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('ter34dgf', 'tert34gdh', 'appKey123', 'appSecret123')
        );
        $objMock->fetchGroups();
    }
    
    
    
    /**
     * Test groups retrieval works fine if token expired.
     * @covers \BogCon\YahooMessengerApi\Client::fetchGroups
     * @covers \BogCon\YahooMessengerApi\Client::isTokenRenewed
     */
    public function testFetchGroupsWorksFineIfTokenExpired()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        $intHttpStatusCode = 0;
        $objMock->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objMock->expects($this->at(1)) // stubbing for fetchGroups to get access token expired
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return 'oauth_problem="token_expired"';
                        }
                    )
                );
        $objMock->expects($this->at(2)) // stubbing for fetchGroups to renew access token
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477963&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        $objMock->expects($this->at(3)) // stubbing for fetchGroups to successfully fetchGroups
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '{"groups":[{"group":{"name":"GroupX","uri":"rcore3.messenger.yahooapis.com\/v1\/group\/GroupX","contacts":[{"contact":{"id":"yahooid1","uri":"rcore3.messenger.yahooapis.com\/v1\/contact\/yahoo\/yahooid1","presence":{"presenceState":0},"clientCapabilities":[{"clientCapability":"richText"},{"clientCapability":"smiley"},{"clientCapability":"buzz"},{"clientCapability":"fileXfer"},{"clientCapability":"voice"},{"clientCapability":"interop"},{"clientCapability":"typing"}],"addressbook":{"id":"12","firstname":"Jonh","lastname":"Doe","lastModified":1376325172}}},{"contact":{"id":"yahooid2","uri":"rcore3.messenger.yahooapis.com\/v1\/contact\/yahoo\/yahooid2","presence":{"presenceState":-1},"clientCapabilities":[],"addressbook":{"id":"3","firstname":"Johnny","lastname":"Doe","lastModified":1192198013}}}]}}],"start":0,"total":1,"count":1}';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        
        $groups = $objMock->fetchGroups();
        $this->assertTrue(is_array($groups));
        $this->assertSame($groups, json_decode('{"groups":[{"group":{"name":"GroupX","uri":"rcore3.messenger.yahooapis.com\/v1\/group\/GroupX","contacts":[{"contact":{"id":"yahooid1","uri":"rcore3.messenger.yahooapis.com\/v1\/contact\/yahoo\/yahooid1","presence":{"presenceState":0},"clientCapabilities":[{"clientCapability":"richText"},{"clientCapability":"smiley"},{"clientCapability":"buzz"},{"clientCapability":"fileXfer"},{"clientCapability":"voice"},{"clientCapability":"interop"},{"clientCapability":"typing"}],"addressbook":{"id":"12","firstname":"Jonh","lastname":"Doe","lastModified":1376325172}}},{"contact":{"id":"yahooid2","uri":"rcore3.messenger.yahooapis.com\/v1\/contact\/yahoo\/yahooid2","presence":{"presenceState":-1},"clientCapabilities":[],"addressbook":{"id":"3","firstname":"Johnny","lastname":"Doe","lastModified":1192198013}}}]}}],"start":0,"total":1,"count":1}', true));
        $this->assertTrue($objMock->isTokenRenewed());
    }
    
    
    
    /**
     * Test notifications retrieval works fine.
     * @covers \BogCon\YahooMessengerApi\Client::fetchNotifications
     */
    public function testFetchNotificationsWorksFine()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        
        $objMock->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
                
        $objMock->expects($this->at(1))
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '{ "@pendingMsg" : 0, "@syncStatus" : 0, "responses" : [ { "message" : { "status" : 1, "sequence" : 4, "sender" : "yahooId1" , "receiver" : "myYahooId" , "msg" : "how are you?" , "timeStamp" : 1378303022, "hash" : "QuyxE57kKbX4vp7K+OP1nTbfJ30hAQ==" , "msgContext" : "QuyxE57kKbX4vp7K+OP1nTbfJ30hAQ=="  } } ] }';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        
        $notifications = $objMock->fetchNotifications(4);
        $this->assertTrue(is_array($notifications));
        $this->assertSame($notifications, json_decode('{ "@pendingMsg" : 0, "@syncStatus" : 0, "responses" : [ { "message" : { "status" : 1, "sequence" : 4, "sender" : "yahooId1" , "receiver" : "myYahooId" , "msg" : "how are you?" , "timeStamp" : 1378303022, "hash" : "QuyxE57kKbX4vp7K+OP1nTbfJ30hAQ==" , "msgContext" : "QuyxE57kKbX4vp7K+OP1nTbfJ30hAQ=="  } } ] }', true));
    }
    
    
    
    /**
     * Test notifications retrieval fails when http status code retreived from curl call is not 200.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @covers \BogCon\YahooMessengerApi\Client::fetchNotifications
     */
    public function testFetchNotificationsThrowsExceptionWhenStatusIsNot200()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        
        $objMock->expects($this->at(0))  // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objMock->expects($this->at(1)) // stubbing for fetchNotifications
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return '';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->fetchNotifications(4);
        $this->fail("Exception should have been thrown");
    }
    
    
    
    /**
     * Test notifications throws exception when bad json is retrieved in response.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @expectedExceptionMessage json
     * @covers \BogCon\YahooMessengerApi\Client::fetchNotifications
     */
    public function testFetchNotificationsThrowsExceptionWhenBadJson()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        
        $objMock->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
                
        $objMock->expects($this->at(1))
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '---bad---json---';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        
        try {
            $objMock->fetchNotifications(10000);
        } catch (\BogCon\YahooMessengerApi\Exception $objEx) {
            if (false === strpos($objEx->getMessage(), 'Json error code')) {
                $this->fail("Exception should have been thrown");
            }
            throw new \BogCon\YahooMessengerApi\Exception('json');
        }
    }
    
    
    
    /**
     * Test notifications retrieval throws exception when trying to access directly, without previously logging in.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @expectedExceptionMessage You have to be logged in in order to perform this action.
     * @covers \BogCon\YahooMessengerApi\Client::fetchNotifications
     */
    public function testFetchNotificationsThrowsExceptionWhenNoPreviouslyLoggedIn()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('ter34dgf', 'tert34gdh', 'appKey123', 'appSecret123')
        );
        $objMock->fetchNotifications(321);
    }
    
    
    
    /**
     * Test notifications retrieval works fine if token expired.
     * @covers \BogCon\YahooMessengerApi\Client::fetchNotifications
     * @covers \BogCon\YahooMessengerApi\Client::isTokenRenewed
     */
    public function testFetchNotificationsWorksFineIfTokenExpired()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        $intHttpStatusCode = 0;
        $objMock->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objMock->expects($this->at(1)) // stubbing for fetchGroups to get access token expired
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return 'oauth_problem="token_expired"';
                        }
                    )
                );
        $objMock->expects($this->at(2)) // stubbing for fetchGroups to renew access token
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477963&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        $objMock->expects($this->at(3)) // stubbing for fetchGroups to successfully fetchGroups
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '{ "@pendingMsg" : 0, "@syncStatus" : 0, "responses" : [ { "message" : { "status" : 1, "sequence" : 4, "sender" : "yahooId1" , "receiver" : "myYahooId" , "msg" : "how are you?" , "timeStamp" : 1378303022, "hash" : "QuyxE57kKbX4vp7K+OP1nTbfJ30hAQ==" , "msgContext" : "QuyxE57kKbX4vp7K+OP1nTbfJ30hAQ=="  } } ] }';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        
        $notifications = $objMock->fetchNotifications(4);
        $this->assertTrue(is_array($notifications));
        $this->assertSame($notifications, json_decode('{ "@pendingMsg" : 0, "@syncStatus" : 0, "responses" : [ { "message" : { "status" : 1, "sequence" : 4, "sender" : "yahooId1" , "receiver" : "myYahooId" , "msg" : "how are you?" , "timeStamp" : 1378303022, "hash" : "QuyxE57kKbX4vp7K+OP1nTbfJ30hAQ==" , "msgContext" : "QuyxE57kKbX4vp7K+OP1nTbfJ30hAQ=="  } } ] }', true));
        $this->assertTrue($objMock->isTokenRenewed());
    }
    
    
    
    /**
     * Test message sending works fine.
     * @covers \BogCon\YahooMessengerApi\Client::sendMessage
     */
    public function testSendMessageWorksFine()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        
        $objMock->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
                
        $objMock->expects($this->at(1))
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->sendMessage('How are you my friend?', 'buddyYahooId');
    }
    
    
    
    /**
     * Test message sending fails when http status code retreived from curl call is not 200.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @covers \BogCon\YahooMessengerApi\Client::sendMessage
     */
    public function testSendMessageThrowsExceptionWhenStatusIsNot200()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        
        $objMock->expects($this->at(0))  // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objMock->expects($this->at(1)) // stubbing for sendMessage
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return '';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->sendMessage('How are you my friend?', 'buddyYahooId');
        $this->fail("Exception should have been thrown");
    }
    
    
    
    /**
     * Test message sending throws exception when trying to access directly, without previously logging in.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @expectedExceptionMessage You have to be logged in in order to perform this action.
     * @covers \BogCon\YahooMessengerApi\Client::sendMessage
     */
    public function testSendMessageThrowsExceptionWhenNoPreviouslyLoggedIn()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('ter34dgf', 'tert34gdh', 'appKey123', 'appSecret123')
        );
        $objMock->sendMessage('How are you my friend?', 'buddyYahooId');
    }
    
    
    
    /**
     * Test message sending works fine if token expired.
     * @covers \BogCon\YahooMessengerApi\Client::sendMessage
     * @covers \BogCon\YahooMessengerApi\Client::isTokenRenewed
     */
    public function testSendMessageWorksFineIfTokenExpired()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        $intHttpStatusCode = 0;
        $objMock->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objMock->expects($this->at(1)) // stubbing for sendMessage to get access token expired
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return 'oauth_problem="token_expired"';
                        }
                    )
                );
        $objMock->expects($this->at(2)) // stubbing for sendMessage to renew access token
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477963&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        $objMock->expects($this->at(3)) // stubbing for sendMessage to successfully sendMessage
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->sendMessage('How are you my friend?', 'buddyYahooId');
        $this->assertTrue($objMock->isTokenRenewed());
    }
    
    
    
    /**
     * Test presence state changing works fine.
     * @covers \BogCon\YahooMessengerApi\Client::changePresenceState
     */
    public function testChangePresenceStateWorksFine()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        
        $objMock->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
                
        $objMock->expects($this->at(1))
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->changePresenceState(\BogCon\YahooMessengerApi\Client::USER_IS_ONLINE, 'I \'m online :)');
    }
    
    
    
    /**
     * Test presence state changing fails when http status code retreived from curl call is not 200.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @covers \BogCon\YahooMessengerApi\Client::changePresenceState
     */
    public function testChangePresenceStateThrowsExceptionWhenStatusIsNot200()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        
        $objMock->expects($this->at(0))  // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objMock->expects($this->at(1)) // stubbing for sendMessage
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return '';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->changePresenceState(\BogCon\YahooMessengerApi\Client::USER_IS_BUSY, 'Very very busy...');
        $this->fail("Exception should have been thrown");
    }
    
    
    
    /**
     * Test presence state changing throws exception when trying to access directly, without previously logging in.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @expectedExceptionMessage You have to be logged in in order to perform this action.
     * @covers \BogCon\YahooMessengerApi\Client::changePresenceState
     */
    public function testChangePresenceStateThrowsExceptionWhenNoPreviouslyLoggedIn()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('ter34dgf', 'tert34gdh', 'appKey123', 'appSecret123')
        );
        $objMock->changePresenceState(\BogCon\YahooMessengerApi\Client::USER_IS_BUSY, 'Very very busy...');
    }
    
    
    
    /**
     * Test presence state changing works fine if token expired.
     * @covers \BogCon\YahooMessengerApi\Client::changePresenceState
     * @covers \BogCon\YahooMessengerApi\Client::isTokenRenewed
     */
    public function testChangePresenceStateWorksFineIfTokenExpired()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        $intHttpStatusCode = 0;
        $objMock->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objMock->expects($this->at(1)) // stubbing for changePresenceState to get access token expired
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return 'oauth_problem="token_expired"';
                        }
                    )
                );
        $objMock->expects($this->at(2)) // stubbing for changePresenceState to renew access token
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477963&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        $objMock->expects($this->at(3)) // stubbing for changePresenceState to successfully changePresenceState
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->changePresenceState(\BogCon\YahooMessengerApi\Client::USER_IS_BUSY, 'Very very busy...');
        $this->assertTrue($objMock->isTokenRenewed());
    }
    
    
    
    /**
     * Test buddy authorization works fine.
     * @covers \BogCon\YahooMessengerApi\Client::authorizeBuddy
     */
    public function testAuthorizeBuddyWorksFine()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        
        $objMock->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
                
        $objMock->expects($this->at(1)) // stubbing for authorizeBuddy
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->authorizeBuddy('buddyYahooId', \BogCon\YahooMessengerApi\Client::BUDDY_ACCEPT);
    }
    
    
    
    /**
     * Test buddy authorization fails when http status code retreived from curl call is not 200.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @expectedExceptionMessage authbuddy
     * @covers \BogCon\YahooMessengerApi\Client::authorizeBuddy
     */
    public function testAuthorizeBuddyThrowsExceptionWhenStatusIsNot200()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        
        $objMock->expects($this->at(0))  // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objMock->expects($this->at(1)) // stubbing for authorizeBuddy
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return '';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        try {
            $objMock->authorizeBuddy('buddyYahooId', Client::BUDDY_DECLINE, 'yahoo', 'I dont know u');
        } catch (\BogCon\YahooMessengerApi\Exception $objEx) {
            if (false === strpos($objEx->getMessage(), 'Could not authorize buddy.')) {
                $this->fail('Exception should have been thrown.');
            }
            throw new \BogCon\YahooMessengerApi\Exception('authbuddy');
        }
    }
    
    
    
    /**
     * Test buddy authorization throws exception when trying to access directly, without previously logging in.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @expectedExceptionMessage You have to be logged in in order to perform this action.
     * @covers \BogCon\YahooMessengerApi\Client::authorizeBuddy
     */
    public function testAuthorizeBuddyThrowsExceptionWhenNoPreviouslyLoggedIn()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('ter34dgf', 'tert34gdh', 'appKey123', 'appSecret123')
        );
        $objMock->authorizeBuddy('buddyYahooId');
    }
    
    
    
    /**
     * Test buddy authorization works fine if token expired.
     * @covers \BogCon\YahooMessengerApi\Client::authorizeBuddy
     * @covers \BogCon\YahooMessengerApi\Client::isTokenRenewed
     */
    public function testAuthorizeBuddyWorksFineIfTokenExpired()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        $intHttpStatusCode = 0;
        $objMock->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objMock->expects($this->at(1)) // stubbing for authorizeBuddy to get access token expired
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return 'oauth_problem="token_expired"';
                        }
                    )
                );
        $objMock->expects($this->at(2)) // stubbing for authorizeBuddy to renew access token
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477963&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        $objMock->expects($this->at(3)) // stubbing for authorizeBuddy to successfully authorizeBuddy
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->authorizeBuddy('buddyYahooId', \BogCon\YahooMessengerApi\Client::BUDDY_ACCEPT);
        $this->assertTrue($objMock->isTokenRenewed());
    }
    
    /**
     * Test check session works fine.
     * @covers \BogCon\YahooMessengerApi\Client::checkSession
     */
    public function testCheckSessionWorksFine()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        
        $objMock->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
                
        $objMock->expects($this->at(1)) // stubbing for checkSession
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '{}';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        $returnedValue = $objMock->checkSession();
        $this->assertTrue(is_array($returnedValue));
        $this->assertSame($returnedValue, json_decode('{}', true));
    }
    
    
    
    /**
     * Test check session fails when http status code retreived from curl call is not 200.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @covers \BogCon\YahooMessengerApi\Client::checkSession
     */
    public function testCheckSessionThrowsExceptionWhenStatusIsNot200()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        
        $objMock->expects($this->at(0))  // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objMock->expects($this->at(1)) // stubbing for checkSession
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return '';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->checkSession();
        $this->fail("Exception should have been thrown");
    }
    
    
    
    /**
     * Test check session fails when invalid json is retrieved as response.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @expectedExceptionMessage json
     * @covers \BogCon\YahooMessengerApi\Client::checkSession
     */
    public function testCheckSessionThrowsExceptionWhenInvalidJson()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        
        $objMock->expects($this->at(0))  // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objMock->expects($this->at(1)) // stubbing for checkSession
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '---bad---json---';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        
        try {
            $objMock->checkSession();
        } catch (\BogCon\YahooMessengerApi\Exception $objEx) {
            if (false === strpos($objEx->getMessage(), 'Json error code')) {
                $this->fail("Exception should have been thrown");
            }
            throw new \BogCon\YahooMessengerApi\Exception('json');
        }
    }
    
    
    
    /**
     * Test check session works fine if token has expired
     * @covers \BogCon\YahooMessengerApi\Client::checkSession
     * @covers \BogCon\YahooMessengerApi\Client::isTokenRenewed
     */
    public function testCheckSessionWorksFineIfTokenExpired()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        $intHttpStatusCode = 0;
        $objMock->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objMock->expects($this->at(1)) // stubbing for checkSession to get access token expired
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return 'oauth_problem="token_expired"';
                        }
                    )
                );
        $objMock->expects($this->at(2)) // stubbing for checkSession to renew access token
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477963&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        $objMock->expects($this->at(3)) // stubbing for checkSession to successfully execute
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '{}';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        $returnedValue = $objMock->checkSession();
        $this->assertTrue(is_array($returnedValue));
        $this->assertSame($returnedValue, json_decode('{}', true));
        $this->assertTrue($objMock->isTokenRenewed());
    }
    
    
    
     /**
     * Test keep session alive works fine.
     * @covers \BogCon\YahooMessengerApi\Client::keepAliveSession
     */
    public function testKeepAliveSessionWorksFine()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        
        $objMock->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
                
        $objMock->expects($this->at(1)) // stubbing for keepAliveSession
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->keepAliveSession();
    }
    
    
    
    /**
     * Test keep session alive fails when http status code retreived from curl call is not 200.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @covers \BogCon\YahooMessengerApi\Client::keepAliveSession
     */
    public function testKeepAliveSessionThrowsExceptionWhenStatusIsNot200()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        
        $objMock->expects($this->at(0))  // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objMock->expects($this->at(1)) // stubbing for keepAliveSession to get access token expired
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return 'oauth_problem="token_expired"';
                        }
                    )
                );
        $objMock->expects($this->at(2)) // stubbing for keepAliveSession to renew access token
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477963&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        $objMock->expects($this->at(3)) // stubbing for keepAliveSession second try
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 500;
                            return '';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->keepAliveSession();
        $this->fail("Exception should have been thrown");
    }
    
    
    
    /**
     * Test keep session alive throws exception when trying to access directly, without previously logging in.
     * @expectedException \BogCon\YahooMessengerApi\Exception
     * @expectedExceptionMessage You have to be logged in in order to perform this action.
     * @covers \BogCon\YahooMessengerApi\Client::keepAliveSession
     */
    public function testKeepAliveSessionThrowsExceptionWhenNoPreviouslyLoggedIn()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('ter34dgf', 'tert34gdh', 'appKey123', 'appSecret123')
        );
        $objMock->keepAliveSession();
    }
    
    
    
    /**
     * Test keep session alive works fine if token has expired
     * @covers \BogCon\YahooMessengerApi\Client::keepAliveSession
     * @covers \BogCon\YahooMessengerApi\Client::isTokenRenewed
     */
    public function testKeepAliveSessionWorksFineIfTokenExpired()
    {
        $objMock = $this->getMock(
            '\BogCon\YahooMessengerApi\Client',
            array('makeApiCall'),
            array('usr', 'pass', 'appKey123', 'appSecret123')
        );
        $intHttpStatusCode = 0;
        $objMock->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objMock->expects($this->at(1)) // stubbing for keepAliveSession to get access token expired
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return 'oauth_problem="token_expired"';
                        }
                    )
                );
        $objMock->expects($this->at(2)) // stubbing for keepAliveSession to renew access token
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477963&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        $objMock->expects($this->at(3)) // stubbing for keepAliveSession to successfully execute
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '';
                        }
                    )
                );
        $objMock->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->keepAliveSession();
        $this->assertTrue($objMock->isTokenRenewed());
    }
    
    
    
    /**
     * Test destructor.
     * @covers \BogCon\YahooMessengerApi\Client::__destruct
     */
    public function testDestruct()
    {
        $objYM = new Client('test', 'testpass', 'testapikey', 'testapisecret');
        unset($objYM);
    }
}
