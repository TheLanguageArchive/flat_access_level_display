# flat_access_level_display

1) Add the following to islandora-compound-prev-next.tpl.php

```
<?php echo theme('flat_access_level_display_display_label', ['roles' => $variables['siblings_detailed'][$sibling['pid']]['roles']]); ?>
```

2) Select "SOLR Flat" inside the Compound Object Solution Pack settings page under "Compound Member Query"

