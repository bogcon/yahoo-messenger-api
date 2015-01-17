<?php
/**
 * Unit test for \BogCon\YahooMessengerApi\Exception class.
 *
 * @author    Bogdan Constantinescu <bog_con@yahoo.com>
 * @copyright Copyright (c) 2013-2015 Bogdan Constantinescu
 * @link      GitHub https://github.com/bogcon/yahoo-messenger-api
 * @license   New BSD License (http://opensource.org/licenses/BSD-3-Clause);
 *            see LICENSE.txt file that came along with this package.
 */
namespace BogCon\YahooMessengerApi\Tests;

/**
 * @covers \BogCon\YahooMessengerApi\Exception
 */
class ExceptionTest extends \PHPUnit_Framework_TestCase
{
    /**
     * Test custom exception extends standard exception.
     * @coversNothing
     */
    public function testIsAnException()
    {
        $objEx = new \BogCon\YahooMessengerApi\Exception('Exception message');
        $this->assertTrue($objEx instanceof \Exception);
    }
}
