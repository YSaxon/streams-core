<?php namespace Anomaly\Streams\Platform\Ui\Grid\Command;

use Anomaly\Streams\Platform\Asset\Asset;
use Anomaly\Streams\Platform\Ui\Grid\GridBuilder;
;

/**
 * Class AddAssets
 *
 * @link          http://anomaly.is/streams-platform
 * @author        AnomalyLabs, Inc. <hello@anomaly.is>
 * @author        Ryan Thompson <ryan@anomaly.is>
 * @package       Anomaly\Streams\Platform\Ui\Grid\Command
 */
class AddAssets
{

    /**
     * The form builder.
     *
     * @var GridBuilder
     */
    protected $builder;

    /**
     * Create a new AddAssets instance.
     *
     * @param GridBuilder $builder
     */
    public function __construct(GridBuilder $builder)
    {
        $this->builder = $builder;
    }

    /**
     * Handle the command.
     *
     * @param Asset $asset
     * @throws \Exception
     */
    public function handle(Asset $asset)
    {
        foreach ($this->builder->getAssets() as $collection => $assets) {

            if (!is_array($assets)) {
                $assets = [$assets];
            }

            foreach ($assets as $file) {

                $filters = explode('|', $file);

                $file = array_shift($filters);

                $asset->add($collection, $file, $filters);
            }
        }
    }
}
