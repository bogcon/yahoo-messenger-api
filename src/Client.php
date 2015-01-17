<?php
/**
 * YahooMessenger Api Client.
 *
 * @author    Bogdan Constantinescu <bog_con@yahoo.com>
 * @copyright Copyright (c) 2013-2015 Bogdan Constantinescu
 * @link      GitHub https://github.com/bogcon/yahoo-messenger-api
 * @license   New BSD License (http://opensource.org/licenses/BSD-3-Clause);
 *            see LICENSE.txt file that came along with this package.
 */
namespace BogCon\YahooMessengerApi;

class Client
{
    /**
     * @var const string    Constants for APIs urls.
     */
    const URL_OAUTH_REQUEST_TOKEN    = 'https://login.yahoo.com/WSLogin/V1/get_auth_token';
    const URL_OAUTH_ACCESS_TOKEN     = 'https://api.login.yahoo.com/oauth/v2/get_token';
    const URL_YM_CREATE_SESSION      = 'http://developer.messenger.yahooapis.com/v1/session';
    const URL_YM_DESTROY_SESSION     = 'http://%SERVER%/v1/session';
    const URL_YM_KEEPALIVE_SESSION   = 'http://%SERVER%/v1/session/keepalive';
    const URL_YM_CUSTOM_AVATARS      = 'http://displayimage.messenger.yahooapis.com/v1/displayImage/custom/%NETWORK%/%USERID%';
    const URL_YM_GROUPS              = 'http://%SERVER%/v1/groups';
    const URL_YM_NOTIFICATIONS       = 'http://%SERVER%/v1/notifications';
    const URL_YM_SEND_MESSAGE        = 'http://%SERVER%/v1/message/%NETWORK%/%TARGETID%';
    const URL_YM_PRESENCE            = 'http://%SERVER%/v1/presence';
    const URL_YM_BUDDY_AUTHORIZATION = 'http://%SERVER%/v1/buddyrequest/%NETWORK%/%CONTACTID%';
    
    /**
     *  @var const int      Constants for user presence statuses.
     */
    const USER_IS_OFFLINE = -1;
    const USER_IS_ONLINE  = 0;
    const USER_IS_BUSY    = 2;
    const USER_IS_IDLE    = 999;
    
    /**
     * @var const int       Accept / decline buddy invitation.
     */
    const BUDDY_ACCEPT  = 1;
    const BUDDY_DECLINE = 0;
    
    /**
     * @var static array    Presence states for buddyStatus|buddyInfo notifications.
     */
    public static $notificationsPresenceStatuses = array(
        0   => 'Online',
        1   => 'Be Right Back',
        2   => 'Busy',
        3   => 'Not At Home',
        4   => 'Not At My Desk',
        5   => 'Not In The Office',
        6   => 'On The Phone',
        7   => 'On Vacation',
        8   => 'Out To Lunch',
        9   => 'Stepped Out',
        10  => 'Away',
        99  => 'Custom',
        999 => 'Idle',
    );
    
    /**
     * @var const int       Curl connect timeout.
     */
    const TIMEOUT = 20;
    
    /**
     * @var const string    Client 's version. Should be 4-part string, such as 1.0.1.0
     */
    const VERSION = '1.0.0.0';
    
    /**
     * @var string          User 's username.
     */
    private $userName;
    
    /**
     * @var string          User 's password.
     */
    private $password;
    
    /**
     * @var string          Application 's key.
     */
    private $appKey;
    
    /**
     * @var string          Application 's secret.
     */
    private $appSecret;
    
    /**
     * @var resource        The curl resource.
     */
    protected $curl;
    
    /**
     * @var array           Array with token info
     */
    protected $tokens;
    
    /**
     * @var array           Array with session info.
     */
    protected $session;
    
    /**
     * @var boolean         Keep track if token was renewed.
     */
    protected $tokenRenewed;
    
    
    
    /**
     * Constructor; initializes stuffs...
     * @param   string     $strUserName     YahooMessenger username.
     * @param   string     $strPassword     YahooMessenger password.
     * @param   string     $strAppKey       API application key.
     * @param   string     $strAppSecret    API application secret.
     * @throws  \BogCon\YahooMessengerApi\Exception  If params are not ok / curl could not be initialized.
     */
    public function __construct($strUserName, $strPassword, $strAppKey, $strAppSecret)
    {
        /* verify username and password */
        if (!is_string($strUserName)) {
            throw new Exception('Invalid param username. Must be a string.');
        }
        $arrUser = explode('@', $strUserName);
        if (count($arrUser) > 2) {
            throw new Exception('Invalid param username. Must contain at most one @.');
        }
        if (!preg_match('/^[a-z0-9_\.\+]{1,32}$/i', $arrUser[0])) {
            throw new Exception('Invalid param username. ID must match [a-z0-9_.+] and must have at most 32 chars.');
        }
        if (isset($arrUser[1]) && !preg_match('/^[a-z0-9_\.\+]{3,64}$/i', $arrUser[1])) {
            throw new Exception('Invalid param username. DNS must match [a-z0-9_.+] and must have at most 64 chars.');
        }
        if (!is_string($strPassword) || mb_strlen($strPassword) > 32) {
            throw new Exception('Invalid param password.');
        }
        if (!is_string($strAppKey) || !mb_strlen($strAppKey)) {
            throw new Exception('Invalid param app key.');
        }
        if (!is_string($strAppSecret) || !mb_strlen($strAppSecret)) {
            throw new Exception('Invalid param app secret.');
        }
        $this->userName  = $strUserName;
        $this->password  = $strPassword;
        $this->appKey    = $strAppKey;
        $this->appSecret = $strAppSecret;

        if (!extension_loaded('curl')) {
            // @codeCoverageIgnoreStart
            throw new Exception('cURL extension is not enabled.');
            // @codeCoverageIgnoreEnd
        }
        $this->curl = curl_init();
        if (false === $this->curl) {
            // @codeCoverageIgnoreStart
            throw new Exception('cURL could not be initialized.');
            // @codeCoverageIgnoreEnd
        }

        $this->setTokens(array());
        $this->setSession(array());
        $this->setTokenRenewed(false);
    }
    
    
    
    /**
     * Makes YM api call.
     * @param   string     $strUrl                      Api call url.
     * @param   string     $strMethod                   Request method (POST|GET|DELETE|PUT...)
     * @param   array      $arrHeaders                  Optional request headers.
     * @param   string     $strPostData                 Request body.
     * @param   boolean    $blnSuprimeResponseHeader    Whether to suprime response 's headers or not.
     * @return  string                                  Api call response.
     * @throws \BogCon\YahooMessengerApi\Exception               If smth went wrong.
     * @codeCoverageIgnore
     */
    protected function makeApiCall(
        $strUrl,
        $strMethod = 'GET',
        array $arrHeaders = array(),
        $strPostData = '',
        $blnSuprimeResponseHeader = false,
        &$intStatus = null
    ) {
        curl_setopt($this->curl, CURLOPT_URL, $strUrl);
        curl_setopt($this->curl, CURLOPT_HTTPHEADER, $arrHeaders);
        curl_setopt($this->curl, CURLOPT_TIMEOUT, self::TIMEOUT);
        curl_setopt($this->curl, CURLOPT_CONNECTTIMEOUT, self::TIMEOUT);
        curl_setopt($this->curl, CURLOPT_MAXREDIRS, 3);
        curl_setopt($this->curl, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($this->curl, CURLOPT_FOLLOWLOCATION, 1);
        curl_setopt($this->curl, CURLOPT_CUSTOMREQUEST, $strMethod);
        curl_setopt($this->curl, CURLOPT_POSTFIELDS, $strPostData);
        curl_setopt($this->curl, CURLOPT_HEADER, !$blnSuprimeResponseHeader);
        curl_setopt(
            $this->curl,
            CURLOPT_USERAGENT,
            'YahooMessenger/1.0 (PHP bogcon/yahoo-messenger-api; ' . self::VERSION . ')'
        );
        curl_setopt($this->curl, CURLOPT_SSL_VERIFYPEER, 0);
        
        $mxdResponse = curl_exec($this->curl);
        if (false === $mxdResponse) {
            throw new Exception(curl_error($this->curl), curl_errno($this->curl));
        }
        $intStatus = curl_getinfo($this->curl, CURLINFO_HTTP_CODE);

        return $mxdResponse;
    }
    
    
    
    /**
     * Checks if request token was set.
     * @return boolean
     */
    public function hasRequestToken()
    {
        return array_key_exists('request', $this->getTokens());
    }
    
    
    
    /**
     * Checks if access token was set.
     * @return boolean
     */
    public function hasAccessToken()
    {
        $arrTokens = $this->getTokens();
        return array_key_exists('access', $arrTokens) && is_array($arrTokens['access'])
               && array_key_exists('oauth_token', $arrTokens['access'])
               && array_key_exists('oauth_token_secret', $arrTokens['access'])
               && array_key_exists('oauth_session_handle', $arrTokens['access']);
    }
    
    
    
    /**
     * Checks if access token was set.
     * @return boolean
     */
    public function hasSession()
    {
        return array_key_exists('sessionId', $this->getSession())
               && array_key_exists('server', $this->getSession());
    }
    
    
    
    /**
     * Getter method for request token; implements lazy instantiation.
     * @return  string  The request token.
     * @throws  \BogCon\YahooMessengerApi\Exception  If could not fetch request token from Yahoo API.
     */
    public function getRequestToken()
    {
        if (!$this->hasRequestToken()) {
            $strUrl = self::URL_OAUTH_REQUEST_TOKEN
                . '?login=' . urlencode($this->userName)
                . '&passwd=' . urlencode($this->password)
                . '&oauth_consumer_key=' . urldecode($this->appKey);

            $strResponse = $this->makeApiCall($strUrl, 'GET', array(), '', true);
            $arrBody = explode('=', $strResponse);
            if (2 != count($arrBody) || mb_strtolower($arrBody[0]) != 'requesttoken') {
                throw new Exception('Could not fetch request token. Api response: ' . $strResponse);
            }
            $this->tokens['request'] = $arrBody[1];
        }
        
        return $this->tokens['request'];
    }
    
    
    
    /**
     * Getter method for access token; implements lazy instantiation.
     * @param   boolean     $force   Whether to renew the access token even if it is already set.
     * @return  array                Array with access token info.
     * @throws  \BogCon\YahooMessengerApi\Exception  If could not fetch access token from Yahoo API.
     */
    public function getAccessToken($force = false)
    {
        if (!$this->hasAccessToken() || $force) {
            $arrQuery = array(
                'oauth_nonce' => uniqid(mt_rand(1, 1000)),
                'oauth_consumer_key' => $this->appKey,
                'oauth_signature_method' => 'PLAINTEXT',
                'oauth_timestamp' => time(),
                'oauth_version' => '1.0',
            );
            
            if ($force && $this->hasAccessToken()) {
                // renew acces token
                $arrQuery['oauth_token'] = $this->tokens['access']['oauth_token'];
                $arrQuery['oauth_signature'] = $this->appSecret . '&' . $this->tokens['access']['oauth_token_secret'];
                $arrQuery['oauth_session_handle'] = $this->tokens['access']['oauth_session_handle'];
            } else {
                // new acces token
                $arrQuery['oauth_token'] = $this->getRequestToken();
                $arrQuery['oauth_signature'] = $this->appSecret . '&';
            }
            
            $strUrl = self::URL_OAUTH_ACCESS_TOKEN . '?' . http_build_query($arrQuery);
            $strResponse = $this->makeApiCall($strUrl, 'GET', array(), '', true);
            $arrBody = array();
            parse_str($strResponse, $arrBody);
            if (count($arrBody) < 4
                || !array_key_exists('oauth_token', $arrBody)
                || !array_key_exists('oauth_token_secret', $arrBody)) {
                throw new Exception('Could not fetch access token. Api response: ' . $strResponse);
            }
            $this->tokens['access'] = $arrBody;
            $this->setTokenRenewed(true);
        }
        
        return $this->tokens['access'];
    }

    
    
    /**
     * Creates session.
     * @param  int $intState The state to log user in; one of the constants
     *                       \BogCon\YahooMessengerApi\Client::USER_IS_* (optional)
     * @param  string $strStatusMessage The presence message of the user. (optional)
     * @return \BogCon\YahooMessengerApi\Client
     * @throws \BogCon\YahooMessengerApi\Exception
     */
    public function logIn($intState = self::USER_IS_ONLINE, $strStatusMessage = '')
    {
        // check state param
        if (!in_array(
            $intState,
            array(
                self::USER_IS_ONLINE,
                self::USER_IS_OFFLINE,
                self::USER_IS_BUSY,
                self::USER_IS_IDLE
            )
        )) {
            $intState = self::USER_IS_ONLINE; // set default value
        }
        $arrPostData = array(
            'presenceState' => $intState,
        );
        if (mb_strlen($strStatusMessage)) {
            $arrPostData['presenceMessage'] = $strStatusMessage;
        }
        
        $strPostData = json_encode($arrPostData);
        $intHttpStatus = 0;
        $strResponse = $this->makeApiCall(
            self::URL_YM_CREATE_SESSION,
            'POST',
            $this->getHeadersForCurlCall($strPostData),
            $strPostData,
            true,
            $intHttpStatus
        );

        if (200 != $intHttpStatus) {
            throw new Exception('Could not create session. Api response: ' . $strResponse);
        }
        
        $arrBody = json_decode($strResponse, true);
        if (JSON_ERROR_NONE != json_last_error()) {
            throw new Exception(
                'Could not create session. '
                . 'Json error code: ' . json_last_error() . '. '
                . 'Api response: ' . $strResponse
            );
        }
        $this->setSession($arrBody);
        return $this;
    }
    
    
    
    /**
     * Check session.
     * @return array
     * @throws \BogCon\YahooMessengerApi\Exception
     */
    public function checkSession()
    {
        $intHttpStatus = 0;
        $strResponse = $this->makeApiCall(
            self::URL_YM_CREATE_SESSION,
            'GET',
            $this->getHeadersForCurlCall(),
            '',
            true,
            $intHttpStatus
        );
        
        /* renew access token if expired and redo the call */
        if (401 == $intHttpStatus && false !== mb_strpos($strResponse, 'oauth_problem="token_expired"')) {
            $this->getAccessToken(true);
            $strResponse = $this->makeApiCall(
                self::URL_YM_CREATE_SESSION,
                'GET',
                $this->getHeadersForCurlCall(),
                '',
                true,
                $intHttpStatus
            );
        }
        
        if (200 != $intHttpStatus) {
            throw new Exception('Could not check session. Api response: ' . $strResponse);
        }
        $arrReturnValue = json_decode($strResponse, true);
        if (JSON_ERROR_NONE != json_last_error()) {
            throw new Exception(
                'Could not check session. '
                . 'Json error code: ' . json_last_error() . '. '
                . 'Api response: ' . $strResponse
            );
        }
        return $arrReturnValue;
    }
    
    
    
    /**
     * Keeps alive user session on Yahoo 's servers.
     * @return \BogCon\YahooMessengerApi\Client
     * @throws \BogCon\YahooMessengerApi\Exception   If not previously logged in, if could not keep alive session.
     */
    public function keepAliveSession()
    {
        if (!$this->hasSession()) {
            throw new Exception('You have to be logged in in order to perform this action.');
        }
        
        $strUrl = str_replace('%SERVER%', $this->session['server'], self::URL_YM_KEEPALIVE_SESSION)
            . '?sid=' . urlencode($this->session['sessionId'])
            . '&notifyServerToken=1';

        $intHttpStatus = 0;
        $strResponse = $this->makeApiCall($strUrl, 'PUT', $this->getHeadersForCurlCall(), '', true, $intHttpStatus);

        /* renew access token if expired and redo the call */
        if (401 == $intHttpStatus && false !== mb_strpos($strResponse, 'oauth_problem="token_expired"')) {
            $this->getAccessToken(true);
            $strResponse = $this->makeApiCall($strUrl, 'PUT', $this->getHeadersForCurlCall(), '', true, $intHttpStatus);
        }

        if (200 != $intHttpStatus || trim($strResponse) != '') {
            throw new Exception('Could not keepalive session. Api response: ' . $strResponse);
        }

        return $this;
    }
    
    
    
    /**
     * Destroys session.
     * @return  \BogCon\YahooMessengerApi\Client
     * @throws  \BogCon\YahooMessengerApi\Exception
     */
    public function logOut()
    {
        if (!$this->hasSession()) {
            return $this;
        }
        
        $strUrl = str_replace('%SERVER%', $this->session['server'], self::URL_YM_DESTROY_SESSION)
            . '?sid=' . urlencode($this->session['sessionId']);

        $intHttpStatus = 0;
        $strResponse = $this->makeApiCall(
            $strUrl,
            'DELETE',
            $this->getHeadersForCurlCall(),
            '',
            true,
            $intHttpStatus
        );

        /* renew access token if expired and redo the call */
        if (401 == $intHttpStatus && false !== mb_strpos($strResponse, 'oauth_problem="token_expired"')) {
            $this->getAccessToken(true);
            $strResponse = $this->makeApiCall(
                $strUrl,
                'DELETE',
                $this->getHeadersForCurlCall(),
                '',
                true,
                $intHttpStatus
            );
        }

        if (200 != $intHttpStatus || trim($strResponse) != '') {
            throw new Exception('Could not log out. Api response: ' . $strResponse);
        }

        return $this;
    }
    
    
    
    /**
     * Retrieve user 's custom avatar.
     * @param  string  $strUserId         User 's id.
     * @param  string  $strNetwork        User 's network.
     * @param  string  $strImgSize        Can take 'small', 'medium', 'full' values.
     * @param  string  $strImgFormat      Can take 'gif', 'jpg', 'png' values.
     * @return string  User 's avatar url.
     * @throws \BogCon\YahooMessengerApi\Exception If could not fetch avatar.
     */
    public function fetchCustomAvatar($strUserId, $strNetwork = 'yahoo', $strImgSize = 'small', $strImgFormat = 'png')
    {
        $strReturnValue = '';

        $strUrl = str_replace(
            array('%USERID%', '%NETWORK%'),
            array($strUserId, $strNetwork),
            self::URL_YM_CUSTOM_AVATARS
        ) . '?size=' . urlencode($strImgSize)
          . '&format=' . urlencode($strImgFormat);

        $intHttpStatus = 0;
        $strResponse = $this->makeApiCall($strUrl, 'HEAD', $this->getHeadersForCurlCall(), '', false, $intHttpStatus);

        /* renew access token if expired and redo the call */
        if (401 == $intHttpStatus && false !== mb_strpos($strResponse, 'oauth_problem="token_expired"')) {
            $this->getAccessToken(true);
            $strResponse = $this->makeApiCall(
                $strUrl,
                'HEAD',
                $this->getHeadersForCurlCall(),
                '',
                false,
                $intHttpStatus
            );
        }

        if (200 != $intHttpStatus) {
            throw new Exception('Could not get user avatar. Api response: ' . $strResponse);
        }

        $arrHeaders = $this->getHeadersFromCurlResponse($strResponse);
        if (array_key_exists('x-yahoo-msgr-imageurl', $arrHeaders)
            && mb_strlen($arrHeaders['x-yahoo-msgr-imageurl'])) {
            $strReturnValue = $arrHeaders['x-yahoo-msgr-imageurl'];
        } else {
            throw new Exception('Could not get user avatar. Api response: ' . $strResponse);
        }
        
        return $strReturnValue;
    }
    
    
    
    /**
     * Retrieve list of groups and users.
     * @return array
     * @throws \BogCon\YahooMessengerApi\Exception   If not previously logged in, or could not fetch groups.
     */
    public function fetchGroups()
    {
        if (!$this->hasSession()) {
            throw new Exception('You have to be logged in in order to perform this action.');
        }
        
        $strUrl = str_replace('%SERVER%', $this->session['server'], self::URL_YM_GROUPS)
            . '?sid=' . urlencode($this->session['sessionId'])
            . '&fields=' . urlencode('+presence')
            . '&fields=' . urlencode('+contacts')
            . '&fields=' . urlencode('+clientcap')
            . '&fields=' . urlencode('+addressbook');
        
        $intHttpStatus = 0;
        $strResponse = $this->makeApiCall($strUrl, 'GET', $this->getHeadersForCurlCall(), '', true, $intHttpStatus);

        /* renew access token if expired and redo the call */
        if (401 == $intHttpStatus && false !== mb_strpos($strResponse, 'oauth_problem="token_expired"')) {
            $this->getAccessToken(true);
            $strResponse = $this->makeApiCall($strUrl, 'GET', $this->getHeadersForCurlCall(), '', true, $intHttpStatus);
        }

        if (200 != $intHttpStatus) {
            throw new Exception('Could not fetch groups. Api response: ' . $strResponse);
        }
        
        $arrReturnValue = json_decode($strResponse, true);
        if (JSON_ERROR_NONE != json_last_error()) {
            throw new Exception(
                'Could not fetch groups. '
                . 'Json error code: ' . json_last_error() . '. '
                . 'Api response: ' . $strResponse
            );
        }
        return $arrReturnValue;
    }
    
    
    
    /**
     * Fetch notifications (messages from other users, other users status changes, etc...)
     *
     * @param  integer  $intSequence    Unique sequence 's number.
     * @return array
     * @throws \BogCon\YahooMessengerApi\Exception If not previously logged in,
     *                                             or could not fetch notifications.
     */
    public function fetchNotifications($intSequence)
    {
        if (!$this->hasSession()) {
            throw new Exception('You have to be logged in in order to perform this action.');
        }
        
        $strUrl = str_replace('%SERVER%', $this->session['server'], self::URL_YM_NOTIFICATIONS)
            . '?sid=' . urlencode($this->session['sessionId'])
            . '&seq=' . intval($intSequence)
            . '&count=100'
            . '&rand=' . uniqid(time() + mt_rand(1, 1000));
        
        $intHttpStatus = 0;
        $strResponse = $this->makeApiCall($strUrl, 'GET', $this->getHeadersForCurlCall(), '', true, $intHttpStatus);

        /* renew access token / session if expired and redo the call */
        if (401 == $intHttpStatus) {
            if (false !== mb_strpos($strResponse, 'oauth_problem="token_expired"')) {
                $this->getAccessToken(true);
                $strResponse = $this->makeApiCall(
                    $strUrl,
                    'GET',
                    $this->getHeadersForCurlCall(),
                    '',
                    true,
                    $intHttpStatus
                );
            }
        }

        if (200 != $intHttpStatus) {
            throw new Exception('Could not fetch notifications. Api response: ' . $strResponse);
        }
        
        $arrReturnValue = json_decode($strResponse, true);
        if (JSON_ERROR_NONE != json_last_error()) {
            throw new Exception(
                'Could not fetch notifications. '
                . 'Json error code: ' . json_last_error() . '. '
                . 'Api response: ' . $strResponse
            );
        }
        return $arrReturnValue;
    }
    
    
    
    /**
     * Send a message to another user.
     * @param  string   $strMsg         The message to send.
     * @param  string   $strUserId      The user 's id to send message to.
     * @param  string   $strNetwork     The user 's network. (optional, default 'yahoo')
     * @return \BogCon\YahooMessengerApi\Client
     * @throws \BogCon\YahooMessengerApi\Exception   If not previously logged in, or could not fetch notifications.
     */
    public function sendMessage($strMsg, $strUserId, $strNetwork = 'yahoo')
    {
        if (!$this->hasSession()) {
            throw new Exception('You have to be logged in in order to perform this action.');
        }
        
        $strUrl = str_replace(
            array('%SERVER%', '%NETWORK%', '%TARGETID%'),
            array($this->session['server'], $strNetwork, $strUserId),
            self::URL_YM_SEND_MESSAGE
        ) . '?sid=' . urlencode($this->session['sessionId']);
        $strPostData = json_encode(
            array(
                'sendAs'  => $this->session['primaryLoginId'],
                'message' => $strMsg,
            )
        );
        $intHttpStatus = 0;
        $strResponse = $this->makeApiCall(
            $strUrl,
            'POST',
            $this->getHeadersForCurlCall($strPostData),
            $strPostData,
            true,
            $intHttpStatus
        );
        
        /* renew access token if expired and redo the call */
        if (401 == $intHttpStatus && false !== mb_strpos($strResponse, 'oauth_problem="token_expired"')) {
            $this->getAccessToken(true);
            $strResponse = $this->makeApiCall(
                $strUrl,
                'POST',
                $this->getHeadersForCurlCall($strPostData),
                $strPostData,
                true,
                $intHttpStatus
            );
        }

        if (200 != $intHttpStatus || trim($strResponse) != '') {
            throw new Exception('Could not send message. Api response: ' . $strResponse);
        }
        return $this;
    }
    
    
    
    /**
     * Updates user 's presence information.
     * @param   int             $intState         Presence state.
     * @param   string          $strMessage       Presence message.
     * @return \BogCon\YahooMessengerApi\Client
     * @throws \BogCon\YahooMessengerApi\Exception   If not previously logged in, if could not change presence state.
     */
    public function changePresenceState($intState, $strMessage)
    {
        if (!$this->hasSession()) {
            throw new Exception('You have to be logged in in order to perform this action.');
        }
        
        $strUrl = str_replace('%SERVER%', $this->session['server'], self::URL_YM_PRESENCE)
            . '?sid=' . urlencode($this->session['sessionId']);
        $strPostData = json_encode(
            array(
                'presenceState' => $intState,
                'presenceMessage' => $strMessage,
            )
        );
        $intHttpStatus = 0;
        $strResponse = $this->makeApiCall(
            $strUrl,
            'PUT',
            $this->getHeadersForCurlCall($strPostData),
            $strPostData,
            true,
            $intHttpStatus
        );
        
        /* renew access token if expired and redo the call */
        if (401 == $intHttpStatus && false !== mb_strpos($strResponse, 'oauth_problem="token_expired"')) {
            $this->getAccessToken(true);
            $strResponse = $this->makeApiCall(
                $strUrl,
                'PUT',
                $this->getHeadersForCurlCall($strPostData),
                $strPostData,
                true,
                $intHttpStatus
            );
        }

        if (200 != $intHttpStatus || trim($strResponse) != '') {
            throw new Exception('Could not change presence. Api response: ' . $strResponse);
        }
        return $this;
    }
    
    
    
    /**
     * Buddylist authorization management.
     * @param   string              $strContactId       Contact 's id.
     * @param   int                 $intOperation       Authorization operation; one of the constants BUDDY_*.
     * @param   string              $strNetwork         Contact 's network.
     * @param   string              $strAuthReason      Authorization reason; max (2000 chars).
     * @return  \BogCon\YahooMessengerApi\Client
     * @throws  \BogCon\YahooMessengerApi\Exception  If not previously logged in, if could not change presence state.
     */
    public function authorizeBuddy(
        $strContactId,
        $intOperation = self::BUDDY_ACCEPT,
        $strNetwork = 'yahoo',
        $strAuthReason = ''
    ) {
        if (!$this->hasSession()) {
            throw new Exception('You have to be logged in in order to perform this action.');
        }
        $strUrl = str_replace(
            array('%SERVER%', '%NETWORK%', '%CONTACTID%'),
            array($this->session['server'], $strNetwork, $strContactId),
            self::URL_YM_BUDDY_AUTHORIZATION
        ) . '?sid=' . urlencode($this->session['sessionId']);

        if (mb_strlen($strAuthReason)) {
            $strPostData = json_encode(array('authReason' => mb_substr(trim($strAuthReason), 0, 2000)));
        } else {
            $strPostData = json_encode(array());
        }
        $intHttpStatus = 0;
        $strMethod = $intOperation == self::BUDDY_ACCEPT ? 'POST' : 'DELETE';
        $strResponse = $this->makeApiCall(
            $strUrl,
            $strMethod,
            $this->getHeadersForCurlCall($strPostData),
            $strPostData,
            true,
            $intHttpStatus
        );

        /* renew access token if expired and redo the call */
        if (401 == $intHttpStatus && false !== mb_strpos($strResponse, 'oauth_problem="token_expired"')) {
            $this->getAccessToken(true);
            $strResponse = $this->makeApiCall(
                $strUrl,
                $strMethod,
                $this->getHeadersForCurlCall($strPostData),
                $strPostData,
                true,
                $intHttpStatus
            );
        }

        if (200 != $intHttpStatus || trim($strResponse) != '') {
            throw new Exception('Could not authorize buddy. Api response: ' . $strResponse);
        }
        
        return $this;
    }
    
    
    
    /**
     * Builds an array with headers.
     * @param   string  $strResponse    HTTP response text.
     * @return  array                   An array with headers,
     *                                  first item in the array is the http_code,
     *                                  the other headers, key is header name lowercased
     */
    protected function getHeadersFromCurlResponse($strResponse)
    {
        $arrReturnValue = array();
        $strHeaderText = mb_substr($strResponse, 0, mb_strpos($strResponse, "\r\n\r\n"));
        foreach (explode("\r\n", $strHeaderText) as $intKey => $strLine) {
            if (0 === $intKey) {
                $arrReturnValue['http_code'] = $strLine;
            } else {
                $arrLine = explode(': ', $strLine);
                $arrReturnValue[mb_strtolower($arrLine[0])] = $arrLine[1];
            }
        }
        return $arrReturnValue;
    }
    
    
    
    /**
     * Retrieve authorization header.
     * @return  string                  The OAuth authorization header.
     */
    protected function getAuthorizationHeader()
    {
        $accessToken = $this->getAccessToken();
        return 'Authorization: OAuth realm="yahooapis.com",'
            . 'oauth_nonce="' . uniqid(mt_rand(1, 1000)) . '",'
            . 'oauth_consumer_key="' . $this->appKey . '",'
            . 'oauth_signature_method="PLAINTEXT",'
            . 'oauth_signature="' . urlencode($this->appSecret . '&' . $accessToken['oauth_token_secret']) . '",'
            . 'oauth_timestamp="' . time() . '",'
            . 'oauth_version="1.0",'
            . 'oauth_token="' . urlencode($accessToken['oauth_token']) . '"';
    }
    
    
    
    /**
     * Retrieve headers for curl call.
     * @param   string|null  $mxdPostData    If set adds extra content type json and content length headers.
     * @return  array                        An array with headers.
     */
    protected function getHeadersForCurlCall($mxdPostData = null)
    {
        $arrReturnValue = array(
            $this->getAuthorizationHeader(),
        );
        if (is_string($mxdPostData)) {
            $arrReturnValue[] = 'Content-Type: application/json;charset=utf-8';
            $arrReturnValue[] = 'Content-Length: ' . mb_strlen($mxdPostData);
        }
        return $arrReturnValue;
    }
    
    
    
    /**
     * Getter method for $tokens.
     * @return array    Array that could have two keys 'request' & 'access'.
     */
    public function getTokens()
    {
        return $this->tokens;
    }
    
    
    
    /**
     * Setter method for $tokens.
     * @param   array       $arrTokens
     * @return  \BogCon\YahooMessengerApi\Client
     */
    public function setTokens(array $arrTokens)
    {
        $this->tokens = $arrTokens;
        return $this;
    }
    
    
    
    /**
     * Getter method for $session.
     * @return array
     */
    public function getSession()
    {
        return $this->session;
    }
    
    
    
    /**
     * Setter method for $session.
     * @param   array       $arrSession
     * @return  \BogCon\YahooMessengerApi\Client
     */
    public function setSession(array $arrSession)
    {
        $this->session = $arrSession;
        return $this;
    }
    
    
    
    /**
     * Setter method for $tokenRenewed.
     * @param   boolean     $blnTokenRenewed
     * @return  \BogCon\YahooMessengerApi\Client
     */
    public function setTokenRenewed($blnTokenRenewed)
    {
        $this->tokenRenewed = (boolean) $blnTokenRenewed;
        return $this;
    }

    
    
    /**
     * Getter method for $tokenRenewed.
     * If it is true, this method also will reset the flag, so a second call to irl will return false.
     * @return array
     */
    public function isTokenRenewed()
    {
        if ($this->tokenRenewed) {
            $this->setTokenRenewed(false);
            return true;
        }
        return $this->tokenRenewed;
    }

    
    
    /**
     * Destructor; frees resources, memory, closes connections, etc....
     */
    public function __destruct()
    {
        if (is_resource($this->curl)) {
            curl_close($this->curl);
        }
    }
}
