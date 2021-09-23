package com.example.handler;

import java.util.HashMap;
import java.util.Map;
import com.example.handler.utils.AuthHandlerUtil;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;
import org.apache.synapse.rest.Handler;
import org.wso2.micro.integrator.security.user.api.UserStoreException;
import com.google.gson.Gson;

/**
 * @author janaka
 */
public class APIAuthHandler  implements Handler {

    private static final Log LOG = LogFactory.getLog(APIAuthHandler.class);

    private String userName;
    private String password;
    private String domain;
    private String[] allowedRoles;

    public void addProperty(String arg0, Object arg1) {
        // TODO Auto-generated method stub

    }

    public Map getProperties() {
        // TODO Auto-generated method stub
        return null;
    }

    /**
     * Set roles Get the property set in the ESB handler with the name 'roles'
     *
     * @param roles comma separated list of roles
     */
    public void setRoles(String roles) {
        if (roles != null) {
            this.allowedRoles = roles.split(",");
        }
    }

    /**
     * Set domain Get the property set in the ESB handler with the name 'domain'
     *
     * @param domain
     *            user store domain
     */
    public void setDomain(String domain) {
        this.domain = domain;
    }

    /**
     * Handle the request
     * Process the basicAuth header and retrieve credentials
     * Expose the user name to security context
     */
    public boolean handleRequest(MessageContext messageContext) {
        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        Object headers = axis2MessageContext.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

        ConfigurationContext axis2ConfigurationContext = axis2MessageContext.getConfigurationContext();

        int tenantId = -1234;
        LOG.debug("Rest API APIAuthHandler tenant: " + tenantId);

        boolean isSuccessful = false;

        if ( headers instanceof Map) {
            Map headersMap = (Map) headers;
            String authHeader = (String) headersMap.get(AuthHandlerConstants.AUTHORIZATION);
            AuthHandlerUtil authHandlerUtil = new AuthHandlerUtil();

            if ((!StringUtils.isEmpty(authHeader) )
                    && authHandlerUtil.getSecurityScheme(authHeader).equals(AuthHandlerConstants.BASIC_SEC_SCHEME)) {
                String credentials = authHandlerUtil.getCredentialString(authHeader);

                if (credentials != null) {
                    credentials = credentials.trim();
                    try {
                        isSuccessful = processSecurity(credentials, tenantId);
                        if (isSuccessful) {
                            // expose security context to messageContext
                            AuthHandlerUtil authUtil = new AuthHandlerUtil();
                            AuthHandlerUtil.Credential cred = authUtil.getDecodedCredentials(credentials);
                            Map<String, Object>  secContextMap = new HashMap<String, Object>();
                            secContextMap.put(AuthHandlerConstants.ISSUER, cred.getUserName());
                            secContextMap.put(AuthHandlerConstants.CLAIMS, new HashMap<String, Object>());

                            Gson gson = new Gson();
                            String secContext = gson.toJson(secContextMap);
                            messageContext.setProperty(AuthHandlerConstants.SEC_CONTEXT,secContext);

                            LOG.debug("User with username : " + userName + " authenticated successfully");
                        } else {
                            headersMap.clear();
                            axis2MessageContext.setProperty(AuthHandlerConstants.HTTP_SC,AuthHandlerConstants.FORBIDDEN_CODE);
                            axis2MessageContext.setProperty(AuthHandlerConstants.NO_ENTITY_BODY, true);
                            messageContext.setProperty(AuthHandlerConstants.RESPONSE, "true");
                            messageContext.setTo(null);
                            Axis2Sender.sendBack(messageContext);
                        }
                    } catch (UserStoreException e) {
                        LOG.error("Unable to execute the authentication process : ",e);
                    } catch (Exception e) {
                        LOG.error("Unable to execute the authentication process : ",e);
                    }
                }
            } else {
                LOG.info("Security headers not present and Unable to complete the authentication process ");
            }
        }
        return isSuccessful;
    }

    public boolean handleResponse(MessageContext arg0) {
        // TODO Auto-generated method stub
        return true;
    }

    /**
     * Process the details in authorization header to validate the user
     *
     * @param credentials
     *            username and password sent in the header
     * @param tenantId
     *            tenantID
     * @return if the user is valid or not
     *
     * @throws UserStoreException throwing UserStoreException
     */
    public boolean processSecurity(String credentials, int tenantId)  throws UserStoreException {

        boolean isAllowed = false;

        String decodedCredentials;
        if (credentials != null) {
            decodedCredentials = new String(new Base64().decode(credentials.getBytes()));
            userName = decodedCredentials.split(":")[0];
            password = decodedCredentials.split(":")[1];

        }

        if (userName != null && password != null && allowedRoles != null) {
            UserValidationManager userValidationManager = new UserValidationManager();
            isAllowed = userValidationManager.validateUser(domain, userName,
                    password, allowedRoles, tenantId);
        } else {
            LOG.debug("Username or password not provided");
        }

        if (!isAllowed) {
            LOG.info("Unable to authenticate the user with the UserName : "
                    + userName);
        }

        return isAllowed;
    }
}