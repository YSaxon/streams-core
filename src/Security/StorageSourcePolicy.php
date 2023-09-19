<?php

namespace Anomaly\Streams\Platform\Security;

use Twig\Sandbox\SourcePolicyInterface;
use Twig\Source;

class StorageSourcePolicy implements SourcePolicyInterface
{
    protected $storagePath;
    public function __construct (){
        $this->storagePath = storage_path();
    }
    public function enableSandbox(Source $source) : bool
    {
        //possibly add a cache for speed
        if ($source === null) {
            return false;
        }
        $sourcePath = $source->getPath();
        //TODO possibly we need to normalize the path here
        return str_contains($sourcePath, $this->storagePath);
    }
}
