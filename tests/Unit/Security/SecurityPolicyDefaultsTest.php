<?php

use Anomaly\Streams\Platform\Security\SecurityPolicyDefaults;

class SecurityPolicyDefaultsTest extends TestCase
{
    public function testAddDefaultsToIndexedArray()
    {
        $original = ['custom1', SecurityPolicyDefaults::INCLUDE_DEFAULTS, 'custom2'];
        $defaults = ['default1', 'default2'];
        $result = SecurityPolicyDefaults::addDefaultsToIndexedArray($original, $defaults);
        $this->assertEquals(['custom1', 'custom2', 'default1', 'default2'], $result);
    }

    public function testAddDefaultsToIndexedArrayNoDefaultsMarker()
    {
        $original = ['custom1', 'custom2'];
        $defaults = ['default1', 'default2'];
        $result = SecurityPolicyDefaults::addDefaultsToIndexedArray($original, $defaults);
        $this->assertEquals(['custom1', 'custom2'], $result);
    }

    public function testAssocArrayMerge()
    {
        $array1 = [
            'key1' => ['val1'],
            'key2' => ['val2'],
        ];
        $array2 = [
            'key2' => ['val3'],
            'key3' => ['val4'],
        ];
        $result = SecurityPolicyDefaults::assoc_array_merge($array1, $array2);
        $this->assertEquals([
            'key1' => ['val1'],
            'key2' => ['val2', 'val3'],
            'key3' => ['val4']
        ], $result);
    }

    public function testAddDefaultsToAssociativeArray()
    {
        $original = [
            'Class1' => ['method1'],
            SecurityPolicyDefaults::INCLUDE_DEFAULTS
        ];
        $defaults = [
            'Class1' => ['defaultMethod1'],
            'Class2' => ['defaultMethod2']
        ];
        $result = SecurityPolicyDefaults::addDefaultsToAssociativeArray($original, $defaults);

        $this->assertEquals([
            'Class1' => ['method1', 'defaultMethod1'],
            'Class2' => ['defaultMethod2']
        ], $result);
    }

    public function testAddDefaultsToAssociativeArrayNoDefaultsMarker()
    {
        $original = [
            'Class1' => ['method1']
        ];
        $defaults = [
            'Class1' => ['defaultMethod1'],
            'Class2' => ['defaultMethod2']
        ];
        $result = SecurityPolicyDefaults::addDefaultsToAssociativeArray($original, $defaults);

        $this->assertEquals([
            'Class1' => ['method1']
        ], $result);
    }

    public function testAddDefaultsToAll()
    {
        $tags = ['customTag', SecurityPolicyDefaults::INCLUDE_DEFAULTS,'customTagTwo'];
        $filters = ['customFilter',SecurityPolicyDefaults::INCLUDE_DEFAULTS, 'customFilterTwo'];
        $functions = ['customFunction', SecurityPolicyDefaults::INCLUDE_DEFAULTS, 'customFunctionTwo'];
        $methods = ['customClass' => ['customMethod'], SecurityPolicyDefaults::INCLUDE_DEFAULTS, 'customClassTwo' => ['customMethodTwo']];
        $properties = ['customClass' => ['customProperty'], SecurityPolicyDefaults::INCLUDE_DEFAULTS, 'customClassTwo' => ['customPropertyTwo']];

        SecurityPolicyDefaults::addDefaultsToAll($tags, $filters, $functions, $methods, $properties);

        // Now $tags, $filters, $functions, $methods, and $properties should have defaults added
        // Check one or two defaults for each to confirm
        $this->assertTrue(in_array('if', $tags));
        $this->assertTrue(in_array('customTag', $tags));
        $this->assertTrue(in_array('customTagTwo', $tags));
        $this->assertFalse(in_array('include', $tags));
        $this->assertFalse(in_array(SecurityPolicyDefaults::INCLUDE_DEFAULTS, $tags));


        $this->assertTrue(in_array('abs', $filters));
        $this->assertTrue(in_array('customFilter', $filters));
        $this->assertTrue(in_array('customFilterTwo', $filters));
        $this->assertFalse(in_array('map', $filters));
        $this->assertFalse(in_array(SecurityPolicyDefaults::INCLUDE_DEFAULTS, $filters));    


        $this->assertTrue(in_array('max', $functions));
        $this->assertTrue(in_array('customFunction', $functions));
        $this->assertTrue(in_array('customFunctionTwo', $functions));
        $this->assertFalse(in_array('include', $functions));
        $this->assertFalse(in_array(SecurityPolicyDefaults::INCLUDE_DEFAULTS, $functions));

        $this->assertTrue(array_key_exists('Twig\Template', $methods));
        $this->assertTrue(array_key_exists('customClass', $methods));
        $this->assertTrue(array_key_exists('customClassTwo', $methods));
        $this->assertFalse(array_key_exists('SomethingElse', $methods));
        $this->assertFalse(in_array(SecurityPolicyDefaults::INCLUDE_DEFAULTS, $methods));


        $this->assertTrue(array_key_exists('Twig\Template', $properties));
        $this->assertTrue(array_key_exists('customClass', $properties));
        $this->assertTrue(array_key_exists('customClassTwo', $properties));
        $this->assertFalse(array_key_exists('SomethingElse', $properties));
        $this->assertFalse(in_array(SecurityPolicyDefaults::INCLUDE_DEFAULTS, $properties));
    }
}
