<?php

class SandboxingTemplateTest extends TestCase
{

    public function testCanBeResolved()
    {
        $this->assertInstanceOf(
            \Anomaly\Streams\Platform\Support\Template::class,
            $this->app->make(\Anomaly\Streams\Platform\Security\SandboxingTemplate::class)
        );
    }

    public function testCanRenderSafeStringTemplate()
    {
        $template = $this->app->make(\Anomaly\Streams\Platform\Security\SandboxingTemplate::class);

        $string = '{{ label }}: {{ 10*5 }}';

        $rendered =  $template->render($string, ['label' => 'test']);

        $this->assertEquals('test: 50', $rendered);
    }

    public function testRenderFailsForUnsafeTemplate()
    {
        $template = $this->app->make(\Anomaly\Streams\Platform\Security\SandboxingTemplate::class);

        $string = '{{ label }}: {{ include("/etc/passwd") }}';

        // Should throw Twig\Sandbox\SecurityNotAllowedFunctionError: Function "include" is not allowed.
        $this->expectException("Twig\Sandbox\SecurityNotAllowedFunctionError");
        $this->expectExceptionMessage('Function "include" is not allowed.');
        $rendered =  $template->render($string, ['label' => 'test']);
    }
}
