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
     * @var array
     */
    private $roleStrength = [

        self::ROLE_ANONYMOUS     => 3,
        self::ROLE_AUTHENTICATED => 2,
        self::ROLE_ACADEMIC      => 1,
    ];

    /**
     * Determining current biggest role
     * based on strength
     *
     * @return string
     */
    public function fetch($roles)
    {
        if (!is_array($roles) || count($roles) === 0) {
            return self::ROLE_SPECIFIC;
        }

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
