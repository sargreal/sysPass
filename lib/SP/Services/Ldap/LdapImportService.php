<?php
/**
 * sysPass
 *
 * @author    nuxsmin
 * @link      https://syspass.org
 * @copyright 2012-2019, Rubén Domínguez nuxsmin@$syspass.org
 *
 * This file is part of sysPass.
 *
 * sysPass is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * sysPass is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 *  along with sysPass.  If not, see <http://www.gnu.org/licenses/>.
 */

namespace SP\Services\Ldap;

use Exception;
use SP\Core\Events\Event;
use SP\Core\Events\EventMessage;
use SP\Core\DataCollection;
use SP\DataModel\UserData;
use SP\DataModel\UserGroupData;
use SP\Providers\Auth\Ldap\Ldap;
use SP\Providers\Auth\Ldap\LdapException;
use SP\Providers\Auth\Ldap\LdapInterface;
use SP\Providers\Auth\Ldap\LdapParams;
use SP\Services\Service;
use SP\Services\User\UserService;
use SP\Services\UserGroup\UserGroupService;
use SP\Services\UserGroup\UserToUserGroupService;
use SP\Providers\Auth\Ldap\LdapUtil;

/**
 * Class UserLdapService
 *
 * @package SP\Services\User
 */
final class LdapImportService extends Service
{
    /**
     * @var int
     */
    protected $totalObjects = 0;
    /**
     * @var int
     */
    protected $syncedObjects = 0;
    /**
     * @var int
     */
    protected $errorObjects = 0;
    /**
     * @var array
     */
    protected $importedUsers = [];
    /**
     * @var array
     */
    protected $importedGroups = [];

    /**
     * @return int
     */
    public function getTotalObjects()
    {
        return $this->totalObjects;
    }

    /**
     * @return int
     */
    public function getSyncedObjects()
    {
        return $this->syncedObjects;
    }

    /**
     * @return int
     */
    public function getErrorObjects()
    {
        return $this->errorObjects;
    }

    /**
     * Sincronizar usuarios de LDAP
     *
     * @param LdapParams       $ldapParams
     * @param LdapImportParams $ldapImportParams
     *
     * @throws LdapException
     */
    public function importGroups(LdapParams $ldapParams, LdapImportParams $ldapImportParams)
    {
        if(!$ldapImportParams->syncGroups) {
            return;
        }
        $ldap = $this->getLdap($ldapParams);

        if (empty($ldapImportParams->filter)) {
            $groups = $ldap->getLdapActions()
            ->getGroups($ldap->getGroupObjectFilter(), null, true);
        } else {
            $groups = $ldap->getLdapActions()
            ->getGroups($ldapImportParams->filter, null, true);
        }

        $numObjects = (int)$groups['count'];

        $this->eventDispatcher->notifyEvent('import.ldap.groups',
            new Event($this, EventMessage::factory()
                ->addDetail(__u('Objects found'), $numObjects))
        );

        $this->totalObjects += $numObjects;

        if ($numObjects > 0) {
            $userGroupService = $this->dic->get(UserGroupService::class);

            foreach ($groups as $result) {
                if ($result instanceof DataCollection) {
                    $userGroupData = new UserGroupData();

                    foreach ($result as $attribute => $value) {

                        switch (strtolower($attribute)) {
                            case 'fullname':
                                $userGroupData->setName($value);
                                break;
                            case 'member':
                                $groupUsers = (array) $value;
                                break;
                            case 'dn':
                                $groupDn = $value;
                                break;
                        }
                    }

                    if (!empty($userGroupData->getName())) {
                        try {
                            $userGroupData->setDescription(__('Imported from LDAP'));

                            if ($userGroupService->checkExistsByName($userGroupData->getName())) {
                                $groupId = $userGroupService->getByName($userGroupData->getName())->getId();
                            } else {
                                $groupId = $userGroupService->create($userGroupData);
                            }
                            $userGroupData->setId($groupId);
                            
                            if (isset($groupUsers) &&
                                $ldapImportParams->syncGroupMembership &&
                                $ldapImportParams->useGroupMembershipAttribute)
                            {
                                $userGroupData->setUsers($groupUsers);
                                $this->importedGroups[$groupDn] = $userGroupData;
                            } 
                            else if ($ldapImportParams->syncGroupMembership)
                            {
                                if (isset($this->importedGroups[$groupDn])) {
                                    $this->importedGroups[$groupDn]->setId($groupId);
                                    $this->importedGroups[$groupDn]->setName($userGroupData->getName());
                                } else {
                                    $this->importedGroups[$groupDn] = $userGroupData;
                                }
                            }

                            $this->eventDispatcher->notifyEvent('import.ldap.progress.groups',
                                new Event($this, EventMessage::factory()
                                    ->addDetail(__u('Group'), sprintf('%s', $userGroupData->getName())))
                            );

                            $this->syncedObjects++;
                        } catch (Exception $e) {
                            processException($e);

                            $this->eventDispatcher->notifyEvent('exception', new Event($e));

                            $this->errorObjects++;
                        }
                    }
                }
            }
        }
    }

    /**
     * @param LdapParams $ldapParams
     *
     * @return LdapInterface
     * @throws LdapException
     */
    protected function getLdap(LdapParams $ldapParams)
    {
        return Ldap::factory($ldapParams, $this->eventDispatcher, $this->config->getConfigData()->isDebug());
    }

    /**
     * @param LdapParams       $ldapParams
     * @param LdapImportParams $ldapImportParams
     *
     * @throws LdapException
     */
    public function importUsers(LdapParams $ldapParams, LdapImportParams $ldapImportParams)
    {
        $ldap = $this->getLdap($ldapParams);

        if (empty($ldapImportParams->filter)) {
            $users = $ldap->getLdapActions()
            ->getUsers($ldap->getGroupMembershipIndirectFilter(), null, true);
        } else {
            $users = $ldap->getLdapActions()
            ->getUsers($ldapImportParams->filter, null, true);
        }

        $numObjects = (int)$users['count'];

        $this->eventDispatcher->notifyEvent('import.ldap.users',
            new Event($this, EventMessage::factory()
                ->addDetail(__u('Objects found'), $numObjects))
        );

        $this->totalObjects += $numObjects;

        if ($numObjects > 0) {
            $userService = $this->dic->get(UserService::class);

            foreach ($users as $result) {
                if ($result instanceof DataCollection) {
                    $userData = new UserData();

                    foreach ($result as $attribute => $value) {

                        switch ($attribute) {
                            case 'fullname':
                                $userData->setName($value);
                                break;
                            case 'login':
                                $userData->setLogin($value);
                                break;
                            case 'mail':
                                $userData->setEmail($value);
                                break;
                            case 'group':
                                $userGroups = (array) $value;
                                break;
                            case 'dn':
                                $dn = $value;
                                break;
                        }
                    }

                    if (!empty($userData->getName())
                        && !empty($userData->getLogin())
                    ) {
                        try {
                            $userData->setNotes(__('Imported from LDAP'));
                            $userData->setUserGroupId($ldapImportParams->defaultUserGroup);
                            $userData->setUserProfileId($ldapImportParams->defaultUserProfile);
                            $userData->setIsLdap(true);

                            if ($userService->checkExistsByLogin($userData->getLogin())) {
                                $currentUserData = $userService->getByLogin($userData->getLogin());
                                if ($ldapImportParams->update) {
                                    $currentUserData->setName($userData->getName());
                                    if (!empty($userData->getEmail())) {
                                        $currentUserData->setEmail($userData->getEmail());
                                    }
                                    $userService->update($currentUserData);
                                }
                                $userData = $currentUserData;
                            } else {
                                $userID = $userService->create($userData);
                                $userData->setId($userID);
                            }

                            if (isset($dn)) {
                                $this->importedUsers[$dn] = $userData;
                            }

                            if(isset($userGroups) &&
                                $ldapImportParams->syncGroups &&
                                $ldapImportParams->syncGroupMembership &&
                                !$ldapImportParams->useGroupMembershipAttribute)
                            {
                                foreach ($userGroups as $groupDn)
                                {
                                    if (isset($this->importedGroups[$groupDn]))
                                    {
                                        $this->importedGroups[$groupDn]->users[] = $dn;
                                    }
                                    else
                                    {
                                        $group = new UserGroupData();
                                        $group->setName(LdapUtil::getGroupName($groupDn));
                                        $group->users[] = $dn;
                                        $this->importedGroups[$groupDn] = $group;
                                    }
                                }
                            }

                            $this->eventDispatcher->notifyEvent('import.ldap.progress.users',
                                new Event($this, EventMessage::factory()
                                    ->addDetail(__u('User'), sprintf('%s (%s)', $userData->getName(), $userData->getLogin())))
                            );

                            $this->syncedObjects++;
                        } catch (Exception $e) {
                            processException($e);

                            $this->eventDispatcher->notifyEvent('exception', new Event($e));

                            $this->errorObjects++;
                        }
                    }
                }
            }
        }
    }

    /**
     * Import Group Memberships.
     * 
     * Requires Users and Groups to be imported right before,
     * because this method uses values saved from these functions
     *
     * @param LdapImportParams $ldapImportParams
     * @return void
     */
    private function importGroupMembership(LdapImportParams $ldapImportParams) {
        if (!$ldapImportParams->syncGroups || !$ldapImportParams->syncGroupMembership) {
            return;
        }

        $userToGroupService = $this->dic->get(UserToUserGroupService::class);

        foreach ($this->importedGroups as $group)
        {
            $userIDs = [];
            $userLogins = [];
            
            foreach ((array) $group->getUsers() as $userDn) {
                if (isset($this->importedUsers[$userDn])) {
                    $userIDs[] = $this->importedUsers[$userDn]->getId();
                    $userLogins[] = $this->importedUsers[$userDn]->getLogin();
                }
            }

            try {
                $userToGroupService->update($group->getId(), $userIDs);
                $this->eventDispatcher->notifyEvent('import.ldap.progress.usergroupmappings',
                    new Event($this, EventMessage::factory()
                        ->addDetail(__u('Group'), $group->getName())
                        ->addDetail(__u('Users'), join(',', $userLogins)))
                    );
            } catch (Exception $e) {
                processException($e);

                $this->eventDispatcher->notifyEvent('exception', new Event($e));

                $this->errorObjects++;
            }
        }
    }

    /**
     * Import Users Groups and GroupMemberships based on the specified parameters
     * 
     * @param LdapParams       $ldapParams
     * @param LdapImportParams $ldapImportParams
     *
     * @throws LdapException
     */
    public function import(LdapParams $ldapParams, LdapImportParams $ldapImportParams)
    {
        $this->importUsers($ldapParams, $ldapImportParams);
        $this->importGroups($ldapParams, $ldapImportParams);
        $this->importGroupMembership($ldapImportParams);
    }
}