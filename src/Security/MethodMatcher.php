<?php
namespace Anomaly\Streams\Platform\Security;

class MethodMatcher
{
    private $allowedMethods;
    private $cache = [];

    public function __construct($allowedMethods)
    {
        foreach ($allowedMethods as $class => $methods) {
            foreach ($methods as $index => $method) {
                $allowedMethods[$class][$index] = strtolower($method);
            }
        }
        $this->allowedMethods = $allowedMethods;
    }


    public function isAllowed($obj, $method)
    {
        $cacheKey = get_class($obj) . "::" . $method;

        // Check cache first
        if (isset($this->cache[$cacheKey])) {
            return $this->cache[$cacheKey];
        }

        $method = strtolower($method); // normalize method name

        foreach ($this->allowedMethods as $class => $methods) {
            if (
                $class === '*' || $obj instanceof $class ||
                str_ends_with($class, '*') && $this->classOrAncestorMatchesPrefix($obj, rtrim($class, '*'))
            ) {
                foreach ($methods as $allowedMethod) {
                    if ($allowedMethod === '*') {
                        $this->cache[$cacheKey] = true;
                        return true;
                    }
                    if ($allowedMethod === $method) {
                        $this->cache[$cacheKey] = true;
                        return true;
                    }
                    if (str_ends_with($allowedMethod, '*') && str_starts_with($method, rtrim($allowedMethod, '*'))) {
                        $this->cache[$cacheKey] = true;
                        return true;
                    }
                }
            }
        }

        // If we reach here, the method is not allowed
        $this->cache[$cacheKey] = false;
        return false;
    }

    private function classOrAncestorMatchesPrefix($obj, $prefix)
    {
        $uniqueClasses = [get_class($obj) => true];
        $queue = [get_class($obj)];

        while (!empty($queue)) {
            $currentClass = array_shift($queue); // Dequeue

            // Check if current class or interface matches the prefix
            if (str_starts_with($currentClass, $prefix)) {
                return true;
            }

            // Handle parent classes
            foreach (class_parents($currentClass) as $ancestor) {
                if (!isset($uniqueClasses[$ancestor])) {
                    $uniqueClasses[$ancestor] = true;
                    $queue[] = $ancestor;
                }
            }

            // Handle implemented interfaces
            foreach (class_implements($currentClass) as $ancestor) {
                if (!isset($uniqueClasses[$ancestor])) {
                    $uniqueClasses[$ancestor] = true;
                    $queue[] = $ancestor;
                }
            }
        }

        return false;
    }

}