<?php
/**
 * @file
 * Flat access level display facets
 */
?>
<div class="islandora-solr-facet-wrapper permission-labels">
    <ul class="islandora-solr-facet permission-labels-list">
        <?php foreach ($facets as $facet) : ?>
        <li>
            <a <?php echo $facet['links']['plus']; ?>>
                <span class="access <?php echo $facet['bucket']; ?>"><?php echo $facet['label']; ?></span>
            </a>
            <span class="count">(<?php echo $facet['count']; ?>)</span>
            <span class="plusminus">
                <a <?php echo $facet['links']['plus']; ?>>+</a>
                <a <?php echo $facet['links']['minus']; ?>>-</a>
            </span>
        </li>
        <?php endforeach; ?>
    </ul>
</div>
