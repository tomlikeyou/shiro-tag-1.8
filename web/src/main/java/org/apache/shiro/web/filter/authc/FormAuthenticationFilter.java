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

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;


/**
 * Requires the requesting user to be authenticated for the request to continue, and if they are not, forces the user
 * to login via by redirecting them to the {@link #setLoginUrl(String) loginUrl} you configure.
 * <p/>
 * <p>This filter constructs a {@link UsernamePasswordToken UsernamePasswordToken} with the values found in
 * {@link #setUsernameParam(String) username}, {@link #setPasswordParam(String) password},
 * and {@link #setRememberMeParam(String) rememberMe} request parameters.  It then calls
 * {@link org.apache.shiro.subject.Subject#login(org.apache.shiro.authc.AuthenticationToken) Subject.login(usernamePasswordToken)},
 * effectively automatically performing a login attempt.  Note that the login attempt will only occur when the
 * {@link #isLoginSubmission(javax.servlet.ServletRequest, javax.servlet.ServletResponse) isLoginSubmission(request,response)}
 * is <code>true</code>, which by default occurs when the request is for the {@link #setLoginUrl(String) loginUrl} and
 * is a POST request.
 * <p/>
 * <p>If the login attempt fails, the resulting <code>AuthenticationException</code> fully qualified class name will
 * be set as a request attribute under the {@link #setFailureKeyAttribute(String) failureKeyAttribute} key.  This
 * FQCN can be used as an i18n key or lookup mechanism to explain to the user why their login attempt failed
 * (e.g. no account, incorrect password, etc.).
 * <p/>
 * <p>If you would prefer to handle the authentication validation and login in your own code, consider using the
 * {@link PassThruAuthenticationFilter} instead, which allows requests to the
 * {@link # loginUrl} to pass through to your application's code directly.
 *
 * @see PassThruAuthenticationFilter
 *
 * FormAuthenticationFilter实现了认证失败后的处理逻辑，即用户在未登录情况下处理的后续操作，
 * 如果用户是一个非登录请求，那么会直接重定向到登录页面（即配置中的loginUrl页面），
 * 如果是一个登录请求，且是GET请求，那么直接放行登录请求，
 * 如果是POST请求，则会从请求中获取默认的username,password等信息去尝试登录，
 *  如果登录成功，则由过滤器直接重定向到登录成功的url上去，并拦截掉用户的请求。
 *  如果登录失败，将失败信息写入到request中去，key值为shiroLoginFailure,然后返回true，过滤器放行，直接到达用户请求的地址，我们就可以在这个请求地址中取到登录失败的数据做相应的操作了
 * @since 0.9
 */
public class FormAuthenticationFilter extends AuthenticatingFilter {

    public static final String DEFAULT_ERROR_KEY_ATTRIBUTE_NAME = "shiroLoginFailure";

    public static final String DEFAULT_USERNAME_PARAM = "username";
    public static final String DEFAULT_PASSWORD_PARAM = "password";
    public static final String DEFAULT_REMEMBER_ME_PARAM = "rememberMe";

    private static final Logger log = LoggerFactory.getLogger(FormAuthenticationFilter.class);

    private String usernameParam = DEFAULT_USERNAME_PARAM;
    private String passwordParam = DEFAULT_PASSWORD_PARAM;
    private String rememberMeParam = DEFAULT_REMEMBER_ME_PARAM;

    private String failureKeyAttribute = DEFAULT_ERROR_KEY_ATTRIBUTE_NAME;

    public FormAuthenticationFilter() {
        setLoginUrl(DEFAULT_LOGIN_URL);
    }

    @Override
    public void setLoginUrl(String loginUrl) {
        String previous = getLoginUrl();
        if (previous != null) {
            this.appliedPaths.remove(previous);
        }
        super.setLoginUrl(loginUrl);
        if (log.isTraceEnabled()) {
            log.trace("Adding login url to applied paths.");
        }
        this.appliedPaths.put(getLoginUrl(), null);
    }

    public String getUsernameParam() {
        return usernameParam;
    }

    /**
     * Sets the request parameter name to look for when acquiring the username.  Unless overridden by calling this
     * method, the default is <code>username</code>.
     *
     * @param usernameParam the name of the request param to check for acquiring the username.
     */
    public void setUsernameParam(String usernameParam) {
        this.usernameParam = usernameParam;
    }

    public String getPasswordParam() {
        return passwordParam;
    }

    /**
     * Sets the request parameter name to look for when acquiring the password.  Unless overridden by calling this
     * method, the default is <code>password</code>.
     *
     * @param passwordParam the name of the request param to check for acquiring the password.
     */
    public void setPasswordParam(String passwordParam) {
        this.passwordParam = passwordParam;
    }

    public String getRememberMeParam() {
        return rememberMeParam;
    }

    /**
     * Sets the request parameter name to look for when acquiring the rememberMe boolean value.  Unless overridden
     * by calling this method, the default is <code>rememberMe</code>.
     * <p/>
     * RememberMe will be <code>true</code> if the parameter value equals any of those supported by
     * {@link org.apache.shiro.web.util.WebUtils#isTrue(javax.servlet.ServletRequest, String) WebUtils.isTrue(request,value)}, <code>false</code>
     * otherwise.
     *
     * @param rememberMeParam the name of the request param to check for acquiring the rememberMe boolean value.
     */
    public void setRememberMeParam(String rememberMeParam) {
        this.rememberMeParam = rememberMeParam;
    }

    public String getFailureKeyAttribute() {
        return failureKeyAttribute;
    }

    public void setFailureKeyAttribute(String failureKeyAttribute) {
        this.failureKeyAttribute = failureKeyAttribute;
    }

    /*
    * 该方法什么时候被调用？在 AccessControlFilter#isAccessAllowed 方法返回false，也就是用户未登录前提下被调用
    * */
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        /*条件成立：说明当前请求是登录页面请求*/
        if (isLoginRequest(request, response)) {
            /*条件成立：说明登录请求是一个post请求，说明该请求带了参数：比如 用户名密码，是实际登录的接口*/
            if (isLoginSubmission(request, response)) {
                if (log.isTraceEnabled()) {
                    log.trace("Login submission detected.  Attempting to execute login.");
                }
                /*则直接执行登录逻辑就好了*/
                return executeLogin(request, response);
            } else {
                /*条件成立：说明当前请求只是跳转到登录页的请求，返回true，让链继续向后执行*/
                if (log.isTraceEnabled()) {
                    log.trace("Login page view.");
                }
                //allow them to see the login page ;)
                return true;
            }
        } else {
            /*走到这里，说明当前请求地址不是登录的地址，前提是没有登录，那么直接跳到登录页面去*/
            if (log.isTraceEnabled()) {
                log.trace("Attempting to access a path which requires authentication.  Forwarding to the " +
                        "Authentication url [" + getLoginUrl() + "]");
            }
            /*重定向到登录页*/
            saveRequestAndRedirectToLogin(request, response);
            return false;
        }
    }

    /**
     * This default implementation merely returns <code>true</code> if the request is an HTTP <code>POST</code>,
     * <code>false</code> otherwise. Can be overridden by subclasses for custom login submission detection behavior.
     *
     * @param request  the incoming ServletRequest
     * @param response the outgoing ServletResponse.
     * @return <code>true</code> if the request is an HTTP <code>POST</code>, <code>false</code> otherwise.
     */
    @SuppressWarnings({"UnusedDeclaration"})
    protected boolean isLoginSubmission(ServletRequest request, ServletResponse response) {
        return (request instanceof HttpServletRequest) && WebUtils.toHttp(request).getMethod().equalsIgnoreCase(POST_METHOD);
    }

    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
        String username = getUsername(request);
        String password = getPassword(request);
        return createToken(username, password, request, response);
    }

    protected boolean isRememberMe(ServletRequest request) {
        return WebUtils.isTrue(request, getRememberMeParam());
    }

    /*重定向到登录成功页*/
    protected boolean onLoginSuccess(AuthenticationToken token, Subject subject,
                                     ServletRequest request, ServletResponse response) throws Exception {
        issueSuccessRedirect(request, response);
        //we handled the success redirect directly, prevent the chain from continuing:
        return false;
    }

    /*将失败信息保存到request域 key：shiroLoginFailure*/
    protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e,
                                     ServletRequest request, ServletResponse response) {
        if (log.isDebugEnabled()) {
            log.debug( "Authentication exception", e );
        }
        setFailureAttribute(request, e);
        //login failed, let request continue back to the login page:
        return true;
    }

    protected void setFailureAttribute(ServletRequest request, AuthenticationException ae) {
        String className = ae.getClass().getName();
        request.setAttribute(getFailureKeyAttribute(), className);
    }

    protected String getUsername(ServletRequest request) {
        return WebUtils.getCleanParam(request, getUsernameParam());
    }

    protected String getPassword(ServletRequest request) {
        return WebUtils.getCleanParam(request, getPasswordParam());
    }


}
