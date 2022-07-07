/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.web.filter.authc;

import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.apache.shiro.web.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * 需要对当前用户进行身份验证的所有过滤器的基类。
 * 该类封装了检查用户是否已在系统中通过身份验证的逻辑，而子类则需要为未经身份验证的请求执行特定的逻辑
 *
 * @since 0.9
 * 实现了 父类 isAccessAllowed 方法，如果用户已认证（已登录）则过滤器直接放行，继续向后执行过滤器链，如果用户没有认证，则交给子类 onAccessDenied 方法处理后续逻辑
 */
public abstract class AuthenticationFilter extends AccessControlFilter {

    public static final String DEFAULT_SUCCESS_URL = "/";

    private String successUrl = DEFAULT_SUCCESS_URL;

    /**
     * Returns the success url to use as the default location a user is sent after logging in.  Typically a redirect
     * after login will redirect to the originally request URL; this property is provided mainly as a fallback in case
     * the original request URL is not available or not specified.
     * <p/>
     * The default value is {@link #DEFAULT_SUCCESS_URL}.
     *
     * @return the success url to use as the default location a user is sent after logging in.
     */
    public String getSuccessUrl() {
        return successUrl;
    }

    /**
     * Sets the default/fallback success url to use as the default location a user is sent after logging in.  Typically
     * a redirect after login will redirect to the originally request URL; this property is provided mainly as a
     * fallback in case the original request URL is not available or not specified.
     * <p/>
     * The default value is {@link #DEFAULT_SUCCESS_URL}.
     *
     * @param successUrl the success URL to redirect the user to after a successful login.
     */
    public void setSuccessUrl(String successUrl) {
        this.successUrl = successUrl;
    }


    /**
     * 当前用户已经登录返回true；反之返回false
     */
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        Subject subject = getSubject(request, response);
        return subject.isAuthenticated() && subject.getPrincipal() != null;
    }

    /**
     * Redirects to user to the previously attempted URL after a successful login.  This implementation simply calls
     * <code>{@link org.apache.shiro.web.util.WebUtils WebUtils}.{@link WebUtils#redirectToSavedRequest(javax.servlet.ServletRequest, javax.servlet.ServletResponse, String) redirectToSavedRequest}</code>
     * using the {@link #getSuccessUrl() successUrl} as the {@code fallbackUrl} argument to that call.
     *
     * @param request  the incoming request
     * @param response the outgoing response
     * @throws Exception if there is a problem redirecting.
     */
    protected void issueSuccessRedirect(ServletRequest request, ServletResponse response) throws Exception {
        WebUtils.redirectToSavedRequest(request, response, getSuccessUrl());
    }

}
