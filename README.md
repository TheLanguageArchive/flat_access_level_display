# flat_access_level_display

Add the following to islandora-compound-prev-next.tpl.php

```
<?php echo theme('flat_access_level_display_display_label', ['pid' => $sibling['pid']]); ?>
```
