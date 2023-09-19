<?php

namespace Anomaly\Streams\Platform\Security;

use Twig\Sandbox\SecurityNotAllowedFilterError;
use Twig\Sandbox\SecurityNotAllowedFunctionError;
use Twig\Sandbox\SecurityNotAllowedMethodError;
use Twig\Sandbox\SecurityNotAllowedPropertyError;
use Twig\Sandbox\SecurityNotAllowedTagError;
use Twig\Sandbox\SecurityPolicyInterface;



/**
 * An improved Twig security policy. This policy is based on the default Twig security policy, but adds the following features:
 * - Allows but does not require the use of default whitelisted properties, by the use of a special value SecurityPolicyDefaults::INCLUDE_DEFAULTS.
 * - Allows using asterisks as wildcards for flexible specifications, especially helpful for methods and properties.
 * - Improves performance by caching the results of method and property checks.
 *
 * @author Yaakov Saxon.
 */

final class SecurityPolicy implements SecurityPolicyInterface
{
    private $allowedTags;
    private $allowedFilters;
    private MethodMatcher $allowedMethods;
    private MethodMatcher $allowedProperties;
    private $allowedFunctions;

/**
 * 
 * For all params, you may include the special value SecurityPolicyDefaults::INCLUDE_DEFAULTS in the array to keep the default whitelisted entities (in addition to those you pass in).
 * 
 * Asterisks function as wildcards:
 * For tags, filters, and functions, passing `['*']` will allow all of that type, though this is not recommended.
 * For methods and properties, you can use `'*'` as the _classname_ to permit the given fields on any class, and an `'*'` either as or at the end of a _fieldname_ (eg `'sortBy*'`) to allow any fields with that prefix. See the defaults for examples.
 * 
 * @param array $allowedTags An array of tags that are allowed. 
 * @param array $allowedFilters An array of filters that are allowed.
 * @param array $allowedMethods An array of methods that are allowed. The array should be in the format of [class => [method1, method2, ...], ...]. 
 * @param array $allowedProperties An array of properties that are allowed. The array should be in the format of [class => [property1, property2, ...], ...].
 * @param array $allowedFunctions An array of functions that are allowed.
 * 
 */
    public function __construct(array $allowedTags = [SecurityPolicyDefaults::INCLUDE_DEFAULTS], array $allowedFilters = [SecurityPolicyDefaults::INCLUDE_DEFAULTS], array $allowedMethods = [SecurityPolicyDefaults::INCLUDE_DEFAULTS], array $allowedProperties = [SecurityPolicyDefaults::INCLUDE_DEFAULTS], array $allowedFunctions = [SecurityPolicyDefaults::INCLUDE_DEFAULTS])
    {
        SecurityPolicyDefaults::processDefaultsToken($allowedTags, $allowedFilters, $allowedFunctions, $allowedMethods, $allowedProperties);
        $this->allowedTags = array_flip($allowedTags);
        $this->allowedFilters = array_flip($allowedFilters);
        $this->allowedFunctions = array_flip($allowedFunctions);
        $this->allowedMethods = new MethodMatcher($allowedMethods);
        $this->allowedProperties = new MethodMatcher($allowedProperties);
    }

    public function checkSecurity($tags, $filters, $functions): void
    {
        if ($tags && !isset($this->allowedTags['*'])) {
            foreach ($tags as $tag) {
                if (! isset($this->allowedTags[$tag])) {
                    throw new SecurityNotAllowedTagError(sprintf('Tag "%s" is not allowed.', $tag), $tag);
                }
            }
        }

        if ($filters && !isset($this->allowedFilters['*'])) {
            foreach ($filters as $filter) {
                if (! isset($this->allowedFilters[$filter])) {
                    throw new SecurityNotAllowedFilterError(sprintf('Filter "%s" is not allowed.', $filter), $filter);
                }
            }
        }

        if ($functions && !isset($this->allowedFunctions['*'])) {
            foreach ($functions as $function) {
                if (! isset($this->allowedFunctions[$function])) {
                    throw new SecurityNotAllowedFunctionError(sprintf('Function "%s" is not allowed.', $function), $function);
                }
            }
        }
    }

    public function checkMethodAllowed($obj, $method): void
    {
        if (!$this->allowedMethods->isAllowed($obj, $method)) {
            $class = \get_class($obj);
            throw new SecurityNotAllowedMethodError(sprintf('Calling "%s" method on a "%s" object is not allowed.', $method, $class), $class, $method);
        }
    }

    public function checkPropertyAllowed($obj, $property): void
    {
        if (!$this->allowedProperties->isAllowed($obj, $property)) {
            $class = \get_class($obj);
            throw new SecurityNotAllowedPropertyError(sprintf('Calling "%s" property on a "%s" object is not allowed.', $property, $class), $class, $property);
        }
    }

    // The functions below are included to make this class drop-in compatible with the built-in Twig SecurityPolicy implementation.

    public function setAllowedTags(array $tags): void
    {
        //if INCLUDE_DEFAULTS is in the array, remove it and add the defaults
        $allowedTags = SecurityPolicyDefaults::processDefaultsTokenForIndexedArray($tags, SecurityPolicyDefaults::TAGS);
        $this->allowedTags = array_flip($allowedTags);
    }

    public function setAllowedFilters(array $filters): void
    {
        $allowedFilters = SecurityPolicyDefaults::processDefaultsTokenForIndexedArray($filters, SecurityPolicyDefaults::FILTERS);
        $this->allowedFilters = array_flip($allowedFilters);
    }

    public function setAllowedMethods(array $methods): void
    {
        $allowedMethods = SecurityPolicyDefaults::processDefaultsTokenForAssociativeArray($methods, SecurityPolicyDefaults::METHODS);
        $this->allowedMethods = new MethodMatcher($allowedMethods);
    }

    public function setAllowedProperties(array $properties): void
    {
        $allowedProperties = SecurityPolicyDefaults::processDefaultsTokenForAssociativeArray($properties, SecurityPolicyDefaults::PROPERTIES);
        $this->allowedProperties = new MethodMatcher($allowedProperties);
    }

    public function setAllowedFunctions(array $functions): void
    {
        $allowedFunctions = SecurityPolicyDefaults::processDefaultsTokenForIndexedArray($functions, SecurityPolicyDefaults::FUNCTIONS);
        $this->allowedFunctions = array_flip($allowedFunctions);
    }


}