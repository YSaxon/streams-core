<?php namespace Anomaly\Streams\Platform\Security;

use Anomaly\Streams\Platform\Application\Application;
use Anomaly\Streams\Platform\Support\Template;
use Illuminate\Contracts\View\Factory;
use Illuminate\Filesystem\Filesystem;

class SandboxingTemplate extends Template {

    public function __construct(
        Factory $view,
        Filesystem $files,
        Application $application
    ) {
        parent::__construct($view, $files, $application);
    }
    public function path($template, $extension = 'twig') {

        $inner_template_path = parent::path($template, $extension);

        $sandboxing_template = '{{ include("' . $inner_template_path . "." . $extension . '" , sandboxed = true) }}';
        
        return parent::path($sandboxing_template, $extension);
    }
}