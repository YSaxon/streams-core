
<?php
use Anomaly\Streams\Platform\Security\MethodMatcher;
class MethodMatcherTest extends TestCase
{

public function testIsAllowedWithAllowedMethod()
{
    $allowedMethods = ['DateTime' => ['getTimezone']];
    $matcher = new MethodMatcher($allowedMethods);

    $obj = new \DateTime();
    $this->assertTrue($matcher->isAllowed($obj, 'getTimezone'));
}

public function testIsAllowedWithNotAllowedMethod()
{
    $allowedMethods = ['DateTime' => ['getTimezone']];
    $matcher = new MethodMatcher($allowedMethods);

    $obj = new DateTime();
    $this->assertFalse($matcher->isAllowed($obj, 'setFoo'));
}

public function testIsAllowedWithWildcard()
{
    $allowedMethods = ['DateTime' => ['*']];
    $matcher = new MethodMatcher($allowedMethods);

    $obj = new DateTime();
    $this->assertTrue($matcher->isAllowed($obj, 'getTimestamp'));
}

public function testIsAllowedWithPrefixWildcard()
{
    $allowedMethods = ['DateTime' => ['get*']];
    $matcher = new MethodMatcher($allowedMethods);

    $obj = new DateTime();
    $this->assertTrue($matcher->isAllowed($obj, 'getTimezone'));
    $this->assertTrue($matcher->isAllowed($obj, 'getFoo'));

}

public function testIsAllowedWithClassWildcard()
{
    $allowedMethods = ['*' => ['getTimezone']];
    $matcher = new MethodMatcher($allowedMethods);

    $obj = new DateTime();
    $this->assertTrue($matcher->isAllowed($obj, 'getTimezone'));
}

public function testIsAllowedWithClassAndMethodWildcard()
{
    $allowedMethods = ['*' => ['*']];
    $matcher = new MethodMatcher($allowedMethods);

    $obj = new DateTime();
    $this->assertTrue($matcher->isAllowed($obj, 'setDate'));
}

public function testIsAllowedWithMultipleClasses()
{
    $allowedMethods = [
        'DateTime' => ['getTimezone'],
        'DateTimeImmutable' => ['*']
    ];
    $matcher = new MethodMatcher($allowedMethods);

    $obj1 = new DateTime();
    $obj2 = new DateTimeImmutable();

    $this->assertTrue($matcher->isAllowed($obj1, 'getTimezone'));
    $this->assertTrue($matcher->isAllowed($obj2, 'getTimestamp'));
    $this->assertFalse($matcher->isAllowed($obj1, 'getTimestamp'));
}

public function testIsAllowedWithMethodWildcardOnlyInOneClass()
{
    $allowedMethods = [
        'DateTime' => ['get*'],
        'DateTimeImmutable' => ['getTimezone']
    ];
    $matcher = new MethodMatcher($allowedMethods);

    $obj1 = new DateTime();
    $obj2 = new DateTimeImmutable();

    $this->assertTrue($matcher->isAllowed($obj1, 'getTimezone'));
    $this->assertTrue($matcher->isAllowed($obj1, 'getTimestamp'));
    $this->assertTrue($matcher->isAllowed($obj2, 'getTimezone'));
    $this->assertFalse($matcher->isAllowed($obj2, 'getTimestamp'));
}

public function testIsAllowedWithInheritedClasses()
{
    $allowedMethods = [
        'DateTimeInterface' => ['getTimestamp']
    ];
    $matcher = new MethodMatcher($allowedMethods);

    $obj1 = new DateTime();
    $obj2 = new DateTimeImmutable();

    $this->assertTrue($matcher->isAllowed($obj1, 'getTimestamp'));
    $this->assertTrue($matcher->isAllowed($obj2, 'getTimestamp'));
}

public function testIsNotAllowedWithClassWildcard()
{
    $allowedMethods = ['*' => ['getTimezone']];
    $matcher = new MethodMatcher($allowedMethods);

    $obj = new DateTime();
    $this->assertFalse($matcher->isAllowed($obj, 'setDate'));
}

}