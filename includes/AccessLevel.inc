<?php
/**
 * Access Level - determines which access level is currently available
 *
 * @author  Ibrahim Abdullah <ibrahim.abdullah@mpi.nl>
 * @package Flat
 */
class AccessLevel
{
    /** @var string */
    const ROLE_ANONYMOUS     = 'anonymous user';

    /** @var string */
    const ROLE_AUTHENTICATED = 'authenticated user';

    /** @var stirng */
    const ROLE_ACADEMIC      = 'academic user';

    /** @var string */
    const ROLE_SPECIFIC      = 'specific';

    /**
     * @var AbstractObject
     */
    private $object;

    /**
     * @var string
     */
    private $pid;

    /**
     * @var Apache_Solr_Service
     */
    private $solr;

    /**
     * @var array
     */
    private $roleStrength = [

        self::ROLE_ANONYMOUS     => 3,
        self::ROLE_AUTHENTICATED => 2,
        self::ROLE_ACADEMIC      => 1,
    ];

    /**
     * Constructor
     *
     * @param string $pid
     */
    public function __construct(string $pid)
    {
        $this->pid = $pid;
    }

    /**
     * Connecting to solr
     *
     * @return Apache_Solr_Service
     */
    public function connect()
    {
        if (null !== $this->solr) {
            return $this->solr;
        }

        $path_parts = parse_url(variable_get('islandora_solr_url', 'localhost:8080/solr'));

        $this->solr = new Apache_Solr_Service($path_parts['host'], $path_parts['port'], $path_parts['path'] . '/');
        $this->solr->setCreateDocuments(0);

        return $this->solr;
    }

    /**
     * Determining current biggest role
     * based on strength
     *
     * @return string
     */
    public function fetch()
    {
        // connect to solr
        $this->connect();

        try {
            $results = $this->solr->search('PID:' . str_replace(':', '\:', $this->pid), 0, 10);
        } catch (Exception $e) {

            drupal_set_message(check_plain(t('Error searching Solr index')) . ' ' . $e->getMessage(), 'error');
            return self::ROLE_SPECIFIC;
        }

        $data = json_decode($results->getRawResponse(), true);

        if ($data['response']['numFound'] < 1) {
            return self::ROLE_SPECIFIC;
        }

        $roles       = $data['response']['docs'][0]['policy_datastream_roles_ms'] ?? [];
        $sortedRoles = [];

        foreach ($roles as $role) {

            if (isset($this->roleStrength[$role])) {
                $sortedRoles[$role] = $this->roleStrength[$role];
            }
        }

        if (count($sortedRoles) === 0) {
            return self::ROLE_SPECIFIC;
        }

        arsort($sortedRoles);
        return key($sortedRoles);
    }
}
