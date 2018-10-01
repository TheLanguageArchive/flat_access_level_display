<?php
/**
 * Access Level facet counter
 */
class AccessLevelFacet
{
    /** @var string */
    const FACET_FIELD = 'compound_policy_datastream_children_access_levels_ms';

    /**
     * @var IslandoraSolrQueryProcessor
     */
    private $query;

    /**
     * Constructor
     *
     * @param IslandoraSolrQueryProcessor $query
     */
    public function __construct(IslandoraSolrQueryProcessor $query)
    {
        $this->query = $query;
    }

    /**
     * Generate theme
     *
     * @return string
     */
    public function render()
    {
        return theme('flat_access_level_display_facets', [
            'facets' => $this->getFacets(),
        ]);
    }

    /**
     * Preparing facets
     *
     * @return array
     */
    private function getFacets()
    {
        $facets  = [];
        $results = $this->getResults();

        foreach ($results as $bucket => $count) {

            $filter   = islandora_solr_lesser_escape(self::FACET_FIELD) . ':"' . islandora_solr_facet_escape($bucket) . '"';
            $facets[] = [

                'count'  => $count,
                'filter' => $filter,
                'bucket' => $bucket,
                'label'  => $this->getLabel($bucket),
                'links'  => $this->generateLink($filter),
            ];
        }

        return $facets;
    }

    /**
     * Get raw facet results
     *
     * @return array
     */
    private function getResults()
    {
        return $this->query->islandoraSolrResult['facet_counts']['facet_fields'][self::FACET_FIELD];
    }

    /**
     * Generate link for filter
     *
     * @param string $filter
     * @return array
     */
    private function generateLink($filter)
    {
        $path   = current_path();
        $params = $this->query->internalSolrParams;

        // Set filter key if there are no filters included.
        if (!isset($params['f'])) {
          $params['f'] = [];
        }

        // Merge recursively to add new filter parameter.
        $query_plus  = array_merge_recursive($params, ['f' => [$filter]]);
        $query_minus = array_merge_recursive($params, ['f' => ['-' . $filter]]);

        $plus = [

            'href'  =>  url($path, ['query' => $query_plus]),
            'rel'   => 'nofollow',
            'class' => 'plus',
        ];

        $minus = [

            'href'  =>  url($path, ['query' => $query_minus]),
            'rel'   => 'nofollow',
            'class' => 'minus',
        ];

        return [

            'plus'  => drupal_attributes($plus),
            'minus' => drupal_attributes($minus),
        ];
    }

    /**
     * Get label
     *
     * @param string $bucket
     * @return string
     */
    public function getLabel(string $bucket)
    {
        $labels = [

            'public'        => 'Public',
            'authenticated' => 'Registered Users',
            'academic'      => 'Academic Users',
            'restricted'    => 'Restricted',
        ];

        return $labels[$bucket] ?? 'Unknown';
    }
}
