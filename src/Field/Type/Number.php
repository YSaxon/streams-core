<?php

namespace Streams\Core\Field\Type;

use Streams\Core\Field\FieldType;
use Streams\Core\Field\Value\NumberValue;
use Streams\Core\Field\Factory\NumberGenerator;

class Number extends FieldType
{
    /**
     * Initialize the prototype.
     *
     * @param array $attributes
     * @return $this
     */
    protected function initializePrototypeAttributes(array $attributes)
    {
        return parent::initializePrototypeAttributes(array_merge([
            'rules' => [
                'numeric',
            ],
        ], $attributes));
    }

    /**
     * Modify the value for storage.
     *
     * @param string $value
     * @return string
     */
    public function modify($value)
    {
        if (is_null($value)) {
            return $value;
        }

        if (is_string($value)) {
            $value = preg_replace('/[^\da-z\.\-]/i', '', $value);
        }

        $float = floatval($value);
        
        if ($float && intval($float) != $float) {
            $value = $float;
        } else {
            $value = intval($value);
        }

        return $value;
    }

    public function expand($value)
    {
        return new NumberValue($value);
    }

    public function generate()
    {
        return $this->generator()->randomNumber();
    }
}
