<?php

namespace Streams\Core\Application;

use Illuminate\Support\Collection;
use Streams\Core\Application\Application;
use Streams\Core\Support\Facades\Streams;
use Streams\Core\Support\Traits\HasMemory;

class ApplicationManager
{

    use HasMemory;

    /**
     * The application collection.
     *
     * @var Collection
     */
    protected $collection;

    /**
     * The active application.
     *
     * @var null|string
     */
    protected $active = null;

    public function __construct()
    {
        $this->collection = Streams::entries('core.applications')->get()->keyBy(function ($item) {
            return $item->id;
        });
    }

    /**
     * Make an application instance.
     *
     * @param string|null $handle
     * @return Application
     */
    public function make($handle = null)
    {
        return $this->collection->get($handle ?: $this->active);
    }

    /**
     * Return the active application.
     *
     * @return Application
     */
    public function active($active = null)
    {
        if (is_object($active)) {
            $active = $active->id;
        }

        if ($active) {
            $this->active = $active;
        }
        
        return $this->collection->get($this->active);
    }

    /**
     * Return the active application handle.
     */
    public function handle()
    {
        return $this->active;
    }

    /**
     * Return the collection instance.
     * 
     * @return Collection
     */
    public function collection()
    {
        return $this->collection;
    }
}
