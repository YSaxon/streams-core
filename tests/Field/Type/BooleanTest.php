<?php

namespace Streams\Core\Tests\Field\Type;

use Streams\Core\Field\Value\BooleanValue;
use Tests\TestCase;
use Streams\Core\Support\Facades\Streams;

class BooleanTest extends TestCase
{

    public function setUp(): void
    {
        $this->createApplication();

        Streams::load(base_path('vendor/streams/core/tests/litmus.json'));
        Streams::load(base_path('vendor/streams/core/tests/fakers.json'));
    }

    public function testNullValues()
    {
        $type = Streams::make('testing.litmus')->fields->boolean->type();

        $this->assertNull($type->modify(null));
        $this->assertNull($type->restore(null));
    }

    public function testCastsToBoolean()
    {
        $type = Streams::make('testing.litmus')->fields->boolean->type();

        $this->assertSame(true, $type->modify(1));
        $this->assertSame(false, $type->restore(0));

        $this->assertSame(true, $type->modify('yes'));
        $this->assertSame(false, $type->restore('no'));
    }

    public function testExpandedValue()
    {
        $test = Streams::repository('testing.litmus')->find('field_types');

        $this->assertInstanceOf(BooleanValue::class, $test->expand('boolean'));
    }

    public function testCanGenerateValue()
    {
        $stream = Streams::make('testing.fakers');

        $this->assertIsBool($stream->fields->boolean->type()->generate());
    }
}
