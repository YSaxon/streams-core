<?php

namespace Streams\Core\Field\Type;

use Streams\Core\Field\Value\ColorValue;

class Color extends Str
{
    /**
     * Initialize the prototype.
     *
     * @param array $attributes
     * @return $this
     */
    protected function initializePrototypeTrait(array $attributes)
    {
        return parent::initializePrototypeTrait(array_merge([
            'rules' => [],
        ], $attributes));
    }

    /**
     * Expand the value.
     *
     * @param $value
     * @return Collection
     */
    public function expand($value)
    {
        return new ColorValue($value);
    }
}
