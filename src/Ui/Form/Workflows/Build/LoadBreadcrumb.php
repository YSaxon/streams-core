<?php

namespace Anomaly\Streams\Platform\Ui\Form\Workflows\Build;

use Anomaly\Streams\Platform\Ui\Form\FormBuilder;
use Anomaly\Streams\Platform\Support\Breadcrumb;

/**
 * Class LoadBreadcrumb
 *
 * @link   http://pyrocms.com/
 * @author PyroCMS, Inc. <support@pyrocms.com>
 * @author Ryan Thompson <ryan@pyrocms.com>
 */
class LoadBreadcrumb
{

    /**
     * Handle the command.
     *
     * @param FormBuilder $builder
     * @param Breadcrumb $breadcrumbs
     */
    public function handle(FormBuilder $builder, Breadcrumb $breadcrumbs)
    {
        if ($breadcrumb = $builder->form->options->get('breadcrumb')) {
            $breadcrumbs->put($breadcrumb, '#');
        }
    }
}
