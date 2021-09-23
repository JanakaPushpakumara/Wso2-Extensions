package com.example.handler.utils;

import java.util.Map;
import com.example.handler.AuthHandlerConstants;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;

/**
 * @author janaka
 */

public class AuthHandlerUtil {

 public Credential getDecodedCredentials(String credentialString){
  String decodedCredentials = new String(new Base64().decode(credentialString.getBytes()));
  Credential cred = new Credential();
   cred.userName = decodedCredentials.split(":")[0];
   cred.password = decodedCredentials.split(":")[1];
  return cred;
 }

 public String getSecurityScheme(String authHeader){
  String scheme = "";
  if(!StringUtils.isEmpty(authHeader) ){
   String [] strArr = authHeader.split(" ");
   if(strArr.length > 0){
    scheme = strArr[0];
   }
  }
  return scheme.trim();
 }

 public String getCredentialString(String authHeader){
  String cred = "";
  if(!StringUtils.isEmpty(authHeader) ){
   String [] strArr = authHeader.split(" ");
   if(strArr.length > 1){
    cred = strArr[1];
   }
  }
  return cred.trim();
 }

 public void sendErrorResponse(String httpStatus, Map headersMap, MessageContext axis2MessageContext, MessageContext messageContext) {
  headersMap.clear();
  axis2MessageContext.setProperty(AuthHandlerConstants.HTTP_SC, httpStatus);
  axis2MessageContext.setProperty(AuthHandlerConstants.NO_ENTITY_BODY, true);
  messageContext.setProperty(AuthHandlerConstants.RESPONSE, "true");
  messageContext.setTo(null);
  Axis2Sender.sendBack(messageContext);
 }

 public static class Credential{

  private String userName;
  private String password;

  public String getUserName() {
   return userName;
  }
  public void setUserName(String userName) {
   this.userName = userName;
  }
  public String getPassword() {
   return password;
  }
  public void setPassword(String password) {
   this.password = password;
  }

 }
}
