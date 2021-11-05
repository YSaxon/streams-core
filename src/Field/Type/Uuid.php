<?php

namespace Streams\Core\Field\Type;

use Streams\Core\Field\FieldType;
use Streams\Core\Field\Value\StrValue;
use Streams\Core\Field\Factory\UuidGenerator;

class Uuid extends FieldType
{

    public function modify($value)
    {
        if (is_null($value)) {
            return $value;
        }

        return (string) $value;
    }

    public function restore($value)
    {
        if (is_null($value)) {
            return $value;
        }

        return (string) $value;
    }

    public function expand($value)
    {
        return new StrValue($value);
    }

    public function generate()
    {
        return $this->generator()->uuid();
    }
}
