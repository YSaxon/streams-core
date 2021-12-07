<?php

namespace Streams\Core\Field\Type;

use Streams\Core\Field\FieldType;
use Illuminate\Support\Facades\App;
use Streams\Core\Field\Value\SelectValue;
use GoldSpecDigital\ObjectOrientedOAS\Objects\Schema;

class Select extends FieldType
{

    public function options(): array
    {
        $options = $this->field->config('options', []);

        if (is_string($options)) {
            return App::call($options);
        }

        return $options;
    }

    public function expand($value)
    {
        return new SelectValue($value);
    }

    public function schema()
    {
        return Schema::string($this->field->handle);
    }

    public function generate()
    {
        return $this->generator()->randomElement(array_keys($this->options()));
    }
}
