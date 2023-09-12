<?php

use Anomaly\Streams\Platform\Security\SecurityPolicy;
use Anomaly\Streams\Platform\Security\SecurityPolicyDefaults;
use Twig\Sandbox\SecurityNotAllowedFilterError;
use Twig\Sandbox\SecurityNotAllowedFunctionError;
use Twig\Sandbox\SecurityNotAllowedMethodError;
use Twig\Sandbox\SecurityNotAllowedPropertyError;
use Twig\Sandbox\SecurityNotAllowedTagError;

class SecurityPolicyTest extends TestCase
{
    public function testConstructorWithNoArgsPullsDefaults()
    {
        $policy = new SecurityPolicy();
        $policy_with_explicit_defaults = new SecurityPolicy(SecurityPolicyDefaults::TAGS, SecurityPolicyDefaults::FILTERS, SecurityPolicyDefaults::METHODS, SecurityPolicyDefaults::PROPERTIES, SecurityPolicyDefaults::FUNCTIONS,);
        assertEquals($policy_with_explicit_defaults, $policy);
    }

    public function testConstructorWithEmptyArraysDoesNotPullDefaults()
    {
        $policy = new SecurityPolicy([], [], [], [], []);
        $policy_with_explicit_defaults = new SecurityPolicy(SecurityPolicyDefaults::TAGS, SecurityPolicyDefaults::FILTERS, SecurityPolicyDefaults::METHODS, SecurityPolicyDefaults::PROPERTIES, SecurityPolicyDefaults::FUNCTIONS);
        assertNotEquals($policy_with_explicit_defaults,$policy);
    }


    public function testCheckSecurityTags()
    {
        $policy = new SecurityPolicy(['a', 'b'], [], [], [], []);
        $policy->checkSecurity(['a','b'], [], []);
        // if no exception is thrown, the test passes
        $this->assertTrue(true);
    }

    public function testCheckSecurityTagsFails()
    {
        $policy = new SecurityPolicy(['a', 'b'], [], [], [], []);

        $this->expectException(SecurityNotAllowedTagError::class);
        $policy->checkSecurity(['a','c'], [], []);
    }

    public function testCheckSecurityFilters()
    {
        $policy = new SecurityPolicy([], ['a', 'b'], [], [], []);
        $policy->checkSecurity([], ['a','b'], []);
        // if no exception is thrown, the test passes
        $this->assertTrue(true);
    }

    public function testCheckSecurityFiltersFails()
    {
        $policy = new SecurityPolicy([], ['a', 'b'], [], [], []);

        $this->expectException(SecurityNotAllowedFilterError::class);
        $policy->checkSecurity([], ['a','c'], []);
    }
    
    public function testCheckSecurityFunctions(){
        $policy = new SecurityPolicy([], [], [], [], ['a','b']);
        $policy->checkSecurity([], [], ['a']);
        // if no exception is thrown, the test passes
        $this->assertTrue(true);
    }
    public function testCheckSecurityFunctionsFails()
    {
        $policy = new SecurityPolicy([], [], [], [], ['a','b']);

        $this->expectException(SecurityNotAllowedFunctionError::class);
        $policy->checkSecurity([], [], ['a','c']);
    }



    public function testCheckMethodAllowedWithSlash()
    {
        $policy = new SecurityPolicy([], [], ['\DateTime' => ['format']],[],[]);
        
        $dateTime = new DateTime();
        $policy->checkMethodAllowed($dateTime, 'format');
        // if no exception is thrown, the test passes
        $this->assertTrue(true);
    }

    public function testCheckMethodAllowedNoSlash()
    {
        $policy = new SecurityPolicy([], [], ['DateTime' => ['format']],[],[]);
        
        $dateTime = new DateTime();
        $policy->checkMethodAllowed($dateTime, 'format');
        // if no exception is thrown, the test passes
        $this->assertTrue(true);
    }

    public function testCheckMethodAllowedFails()
    {
        $policy = new SecurityPolicy([], [], ['\DateTime' => ['format']],[],[]);
        
        $dateTime = new \DateTime();

        $this->expectException(SecurityNotAllowedMethodError::class);
        $policy->checkMethodAllowed($dateTime, 'add');
    }

    public function testCheckPropertyAllowed()
    {
        $policy = new SecurityPolicy([], [], [], ['stdClass' => ['property1'], []]);
        
        $obj = new \stdClass();
        $obj->property1 = "test";

        $policy->checkPropertyAllowed($obj, 'property1');
        // if no exception is thrown, the test passes
        $this->assertTrue(true);
    }

    public function testCheckPropertyAllowedFails()
    {
        $policy = new SecurityPolicy([], [], [], ['stdClass' => ['property1']], []);
        
        $obj = new \stdClass();
        $obj->property1 = "test";

        $this->expectException(SecurityNotAllowedPropertyError::class);
        $policy->checkPropertyAllowed($obj, 'property2');
    }
}