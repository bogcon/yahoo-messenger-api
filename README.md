yahoo-messenger-api v1.0.0
================================================
###A PHP client for Yahoo! Messenger API  
[![Build Status](https://secure.travis-ci.org/bogcon/yahoo-messenger-api.png?branch=master)](http://travis-ci.org/bogcon/yahoo-messenger-api)
[![Coverage Status](https://coveralls.io/repos/bogcon/yahoo-messenger-api/badge.png?branch=master)](https://coveralls.io/r/bogcon/yahoo-messenger-api)
[![Latest Stable Version](https://poser.pugx.org/bogcon/yahoo-messenger-api/v/stable.png)](https://packagist.org/packages/bogcon/yahoo-messenger-api)  

Features
--------------------
 - login
 - logout
 - avatar retrieval
 - groups with contacts list retrieval
 - notifications retrieval (messages, buddy requests...)
 - messages sending
 - authorizing buddies
 - checking yahoo session & keeping it alive

Installation
-------------

1. Using [Composer](https://getcomposer.org/)  

 Add the following to your `composer.json` file located in the root directory of your project.

 ```js
 {
        "require": {
            "bogcon/yahoo-messenger-api": "dev-master"
        }
 }
 ```  
 Then you can run the Composer install/update command from the directory containing the `composer.json` file 
 ```sh
 # download composer (skip the next command if you already have composer)
 $ curl -sS https://getcomposer.org/installer | php
 
 # install dependencies
 $ php composer.phar install
 $ php composer.phar update
 ```
2. Using GIT  

 ```sh
 git clone https://github.com/bogcon/yahoo-messenger-api.git
 ```

3. Download the ZIP archive from [here](https://github.com/bogcon/yahoo-messenger-api/archive/master.zip)  

Usage example
--------------------
```php
try {
    // initialize client
    $objYmClient = new \BogCon\YahooMessengerApi\Client('myYahooUsername', 'myYahooPass', 'app_key', 'app_secret');
    // send a message to a friend
    $objYmClient->logIn(\BogCon\YahooMessengerApi\Client::USER_IS_OFFLINE) // login as Invisible
        ->sendMessage('Hello...Just entered to remind you about our meeting from tomorrow. Bye, see ya.', 'myBuddyId')
        ->logOut();
    echo 'Successfully transmitted message to my friend.';
} catch (\BogCon\YahooMessengerApi\Exception $objEx) {
    echo 'Something went bad: ' . $objEx->getMessage();
}
```  

A simplistic browser based Yahoo Messenger chat that uses this library can be found [here](https://github.com/bogcon/webym).

Yahoo API documentation
--------------------
[http://developer.yahoo.com/messenger/guide/ch02.html](http://developer.yahoo.com/messenger/guide/ch02.html)

License [![License](https://poser.pugx.org/bogcon/yahoo-messenger-api/license.svg)](https://packagist.org/packages/bogcon/yahoo-messenger-api)
--------------------
`yahoo-messenger-api` is released under the `New BSD License` which is the 3-clause BSD license.  
You can find a copy of this license in [LICENSE.txt](LICENSE.txt).