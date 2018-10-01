<?php
/**
 * @file
 * Flat permissions - permission labels template.
 */
?>
<?php if ($access_level) : ?>
<div class="permission-labels">
    <?php if ($access_level === AccessLevel::ROLE_ANONYMOUS) : ?>
        <span class="access public">Public</span>
    <?php endif; ?>
    <?php if ($access_level === AccessLevel::ROLE_AUTHENTICATED) : ?>
        <span class="access authenticated">Registered Users</span>
    <?php endif; ?>
    <?php if ($access_level === AccessLevel::ROLE_ACADEMIC) : ?>
        <span class="access academic">Academic Users</span>
    <?php endif; ?>
    <?php if ($access_level === AccessLevel::ROLE_SPECIFIC) : ?>
        <span class="access restricted">Restricted</span>
    <?php endif; ?>
</div>
<?php endif; ?>
