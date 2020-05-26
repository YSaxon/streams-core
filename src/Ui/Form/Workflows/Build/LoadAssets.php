<?php

namespace Anomaly\Streams\Platform\Ui\Form\Workflows\Build;

use Anomaly\Streams\Platform\Asset\Facades\Assets;
use Anomaly\Streams\Platform\Ui\Form\FormBuilder;
use Anomaly\Streams\Platform\Support\Breadcrumb;

/**
 * Class LoadAssets
 *
 * @link   http://pyrocms.com/
 * @author PyroCMS, Inc. <support@pyrocms.com>
 * @author Ryan Thompson <ryan@pyrocms.com>
 */
class LoadAssets
{

    /**
     * Handle the command.
     *
     * @param FormBuilder $builder
     * @param Breadcrumb $breadcrumbs
     */
    public function handle(FormBuilder $builder, Breadcrumb $breadcrumbs)
    {

        //Assets::collection('scripts.js', 'public::vendor/anomaly/core/js/form/form.js');

        foreach ($builder->assets as $collection => $assets) {
            Assets::collection($collection)->merge($assets);
        }
    }
}
