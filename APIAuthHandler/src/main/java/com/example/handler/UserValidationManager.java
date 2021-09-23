package com.example.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.micro.integrator.security.MicroIntegratorSecurityUtils;
import org.wso2.micro.integrator.security.user.api.UserStoreManager;
import org.wso2.micro.integrator.security.user.api.UserStoreException;
import java.util.Arrays;

/**
 * @author janaka
 */
public class UserValidationManager {

    private static final Log log = LogFactory.getLog(UserValidationManager.class);

    /**
     * Validate user by authentication and authorization
     *
     * @param domain       user store domain user belongs to
     * @param userName     username of the user
     * @param password     password of the user
     * @param allowedRoles list of roles allowed to access the service
     * @param tenantId     tenantId related to the user
     * @return if the user is allowed to access the service

     */
    public boolean validateUser(String domain, String userName, String password, String[] allowedRoles, int tenantId) throws UserStoreException {

        boolean isValidUser = false;
        boolean isAuthenticated = false;
        boolean isAuthorized = false;

        UserStoreManager userStoreManager = MicroIntegratorSecurityUtils.getUserStoreManager();
        String domainQualifiedUser = getDomainQualifiedUserName(userName, domain);
        isAuthenticated = authenticateUser(domainQualifiedUser, password, userStoreManager, tenantId);
        //Only try to authorize the user if authentication is successful
        if (isAuthenticated) {
            isAuthorized = authorizeUser(allowedRoles, domainQualifiedUser, tenantId, domain, userStoreManager);
        }
        if (isAuthenticated && isAuthorized) {
            isValidUser = true;
        }
        return isValidUser;
    }

    /**
     * Authenticate the user with the given username and password
     *
     * @param userName username of the user
     * @param password password of the user
     * @return if the user is authenticated
     * @throws UserStoreException
     */
    private boolean authenticateUser(String userName, String password, UserStoreManager userStoreManager, int tenantId) throws UserStoreException {
        boolean isAuthenticated = false;

        if (userStoreManager != null) {
            try {
                isAuthenticated = userStoreManager.authenticate(userName, password);
            } catch (UserStoreException e) {
                throw new UserStoreException("Error authenticating. Tenant id " + tenantId + " user name " + userName, e);
            }
        } else {
            log.debug("UserStoreManager could not be retrieved");
        }

        return isAuthenticated;
    }

    /**
     * Authorize the user based on the roles
     *
     * @param allowedRoles roles allowed to access the service
     * @param userName     username of the user
     * @param tenantId     tenantId related to the user
     * @return if the user is has the role required to access the service
     * @throws UserStoreException
     */
    private boolean authorizeUser(String[] allowedRoles, String userName, int tenantId, String domain, UserStoreManager userStoreManager) throws UserStoreException {

        boolean accessibility = false;
        if (userStoreManager != null) {
            String[] roles;
            try {
                // get the roles assigned to the user
                roles = userStoreManager.getRoleListOfUser(userName);

                // check if the user has a role required to access the service
                for (String role : allowedRoles) {
                    role = getDomainQualifiedRole(role, domain);
                    if (Arrays.asList(roles).contains(role)) {
                        accessibility = true;
                        break;
                    }
                }
            } catch (UserStoreException e) {
                throw new UserStoreException("Error validating user roles. Tenant id " + tenantId + " user name " + userName, e);
            }
        } else {
            log.debug("UserStoreManager could not be retrieved");
        }

        if (!accessibility) {
            log.info("Unable to authorize the user with the UserName : " + userName);
        }

        return accessibility;
    }

    /**
     * Get the domain qualified user name
     * Append the domain to the username i.e domainName/useName
     *
     * @param userName user name of the user
     * @return domain qualified username
     */
    private String getDomainQualifiedUserName(String userName, String domain) {
        String domainQualifiedUserName;
        //if the domain is not provided, consider as user belonging to primary user store
        //Therefore the domain qualified user name is as same as the provided userName
        if (domain == null) {
            domainQualifiedUserName = userName;
        } else {
            domainQualifiedUserName = domain + "/" + userName;
        }
        return domainQualifiedUserName;
    }

    /**
     * Get the domain qualified role name
     * Append the domain to the role name i.e domainName/roleName
     *
     * @param role allowed role
     * @return domain qualified role name
     */
    private String getDomainQualifiedRole(String role, String domain) {
        String domainQualifiedUserRole;
        //if the domain is not provided, consider as role belonging to primary user store
        //Therefore the domain qualified role name is as same as the provided role
        if (domain == null) {
            domainQualifiedUserRole = role;
        } else {
            domainQualifiedUserRole = domain + "/" + role;
        }
        return domainQualifiedUserRole;
    }
}
