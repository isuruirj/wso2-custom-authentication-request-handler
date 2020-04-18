/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.sample.custom.auth.request.handler;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.DefaultAuthenticationRequestHandler;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthResponseWrapper;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CustomRequestAuthenticationHandler extends DefaultAuthenticationRequestHandler {

    private static final Log log = LogFactory.getLog(CustomRequestAuthenticationHandler.class);
    private static List<String> serviceProviderNames;

    /**
     * To get the qualified service providers from the configuration file to drop the authenticators.
     *
     * @return
     */
    public static void getQualifiedServiceProviders() {

        String qualifiedServiceProviders = IdentityUtil.getProperty("CustomAuthenticationHandlerConfig.ServiceProviders");
        if (StringUtils.isEmpty(qualifiedServiceProviders)) {
            log.warn("No Service providers has been defined to remove authentication query param.");
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Service providers listed to remove authenticators param : " + qualifiedServiceProviders);
            }
            serviceProviderNames = Arrays.asList(qualifiedServiceProviders.split("\\s*,\\s*"));
        }
    }

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AuthenticationContext context) throws FrameworkException {

        super.handle(request, response, context);

        if (response instanceof CommonAuthResponseWrapper && ((CommonAuthResponseWrapper) response).isRedirect()) {
            if (serviceProviderNames == null) {
                serviceProviderNames = new ArrayList<String>();
                getQualifiedServiceProviders();
            }
            // Check if the query param removal need to be done for this tenant and sp
            String spTenantCombination = context.getServiceProviderName() + "@" + context.getTenantDomain();
            if (!serviceProviderNames.isEmpty() && serviceProviderNames.contains(spTenantCombination)) {
                String redirectUrl = ((CommonAuthResponseWrapper) response).getRedirectURL();
                if (StringUtils.isNotBlank(redirectUrl)) {
                    redirectUrl = removeAuthenticatorsQueryParam(redirectUrl);
                }
                // Set the modified redirect URL
                try {
                    response.sendRedirect(redirectUrl);
                } catch (IOException e) {
                    throw new FrameworkException("Error while redirecting to authentication endpoint.", e);
                }
            }
        }
    }

    /**
     * Remove authenticators param from the redirect URL
     *
     * @param url
     * @return
     */
    private String removeAuthenticatorsQueryParam(String url) {

        if (url.contains("/authenticationendpoint/login.do")) {
            url = url.replaceAll("[&?]authenticators.*?(?=&|\\?|$)", "");
        }

        return url;
    }

}
