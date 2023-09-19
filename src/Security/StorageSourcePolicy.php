<?php

namespace Anomaly\Streams\Platform\Security;
use Anomaly\Streams\Platform\Application\Application;


use Twig\Sandbox\SourcePolicyInterface;
use Twig\Source;

class StorageSourcePolicy implements SourcePolicyInterface
{
    protected $storagePath;
    public function __construct(Application $application)
    {
        $this->storagePath = realpath($application->getStoragePath());
        $this->cache = [];
    }
    public function enableSandbox(Source $source = null) : bool
    {
        if ($source === null) {
            return false;
        }

        $source_path = $source->getPath();

        if (isset($this->cache[$source_path])) {
            return $this->cache[$source_path];
        }
        $real_source_path = realpath($source_path);
        $is_path_in_storage = str_starts_with($real_source_path, $this->storagePath);

        $this->cache[$source_path] = $is_path_in_storage;
        return $is_path_in_storage;
    }
}
