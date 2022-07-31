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
package org.apache.shiro.web.servlet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

/**
 * 过滤器的基类，保证每个请求只在任何 servlet容器上执行一次；确保每个过滤器对一个请求只执行一次（实现方式：request域中添加属性）
 * <p/>
 * The {@link #getAlreadyFilteredAttributeName} method determines how
 * to identify that a request is already filtered. The default implementation
 * is based on the configured name of the concrete filter instance.
 * <h3>Controlling filter execution</h3>
 * 1.2 introduced the {@link #isEnabled(javax.servlet.ServletRequest, javax.servlet.ServletResponse)} method and
 * {@link #isEnabled()} property to allow explicit control over whether the filter executes (or allows passthrough)
 * for any given request.
 * <p/>
 * <b>NOTE</b> This class was initially borrowed from the Spring framework but has continued modifications.
 * @since 0.1
 */
public abstract class OncePerRequestFilter extends NameableFilter {

    private static final Logger log = LoggerFactory.getLogger(OncePerRequestFilter.class);

    /**
     * Suffix that gets appended to the filter name for the "already filtered" request attribute.
     *
     * @see #getAlreadyFilteredAttributeName
     */
    public static final String ALREADY_FILTERED_SUFFIX = ".FILTERED";

    /**
     * 明确控制过滤器是否对任何给定请求执行（或允许通过）默认为true，代表都执行
     * 确定某个过滤器对任何请求是否执行，默认过滤器执行，当不需要某个过滤器对任何请求执行的时候，只需要将该过滤器的该属性设置为false
     * @see #isEnabled()
     */
    private boolean enabled = true;

    /**
     * Returns {@code true} if this filter should <em>generally</em><b>*</b> execute for any request,
     * {@code false} if it should let the request/response pass through immediately to the next
     * element in the {@link FilterChain}.  The default value is {@code true}, as most filters would inherently need
     * to execute when configured.
     * <p/>
     * <b>*</b> This configuration property is for general configuration for any request that comes through
     * the filter.  The
     * {@link #isEnabled(javax.servlet.ServletRequest, javax.servlet.ServletResponse) isEnabled(request,response)}
     * method actually determines whether or not if the filter is enabled based on the current request.
     *
     * @return {@code true} if this filter should <em>generally</em> execute, {@code false} if it should let the
     * request/response pass through immediately to the next element in the {@link FilterChain}.
     * @since 1.2
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * 设置某个过滤器是否对任何请求执行
     * @param enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * This {@code doFilter} implementation stores a request attribute for
     * "already filtered", proceeding without filtering again if the
     * attribute is already there.
     *
     * @see #getAlreadyFilteredAttributeName
     * @see #shouldNotFilter
     * @see #doFilterInternal
     */
    public final void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String alreadyFilteredAttributeName = getAlreadyFilteredAttributeName();
        /*从请求头获取信息，判断具体的过滤器 是否已经执行过了，条件成立：说明当前过滤器对这个url请求已经执行过了 则跳过当前过滤器，继续向后执行*/
        if ( request.getAttribute(alreadyFilteredAttributeName) != null ) {
            log.trace("Filter '{}' already executed.  Proceeding without invoking this filter.", getName());
            filterChain.doFilter(request, response);
        } else //noinspection deprecation
            if (/* added in 1.2: */ !isEnabled(request, response) ||
                /* retain backwards compatibility: */ shouldNotFilter(request) ) {
                /*条件成立：说明该过滤器不需要执行，直接跳过，继续向后执行*/
            log.debug("Filter '{}' is not enabled for the current request.  Proceeding without invoking this filter.",
                    getName());
            filterChain.doFilter(request, response);
        } else {
            /*大多数情况，会走这里，执行该过滤器*/
            log.trace("Filter '{}' not yet executed.  Executing now.", getName());
            /*请求头设置信息 代表当前过滤器已经执行，后面代码块是启动过滤器的逻辑*/
            request.setAttribute(alreadyFilteredAttributeName, Boolean.TRUE);
            try {
                /*模板方法 提供给子类实现 具体业务地方*/
                doFilterInternal(request, response, filterChain);
            } finally {
                /*一次请求处理完成了，将当前过滤器的请求头信息删除*/
                request.removeAttribute(alreadyFilteredAttributeName);
            }
        }
    }

    /**
     * Returns {@code true} if this filter should filter the specified request, {@code false} if it should let the
     * request/response pass through immediately to the next element in the {@code FilterChain}.
     * <p/>
     * This default implementation merely returns the value of {@link #isEnabled() isEnabled()}, which is
     * {@code true} by default (to ensure the filter always executes by default), but it can be overridden by
     * subclasses for request-specific behavior if necessary.  For example, a filter could be enabled or disabled
     * based on the request path being accessed.
     * <p/>
     * <b>Helpful Hint:</b> if your subclass extends {@link org.apache.shiro.web.filter.PathMatchingFilter PathMatchingFilter},
     * you may wish to instead override the
     * {@link org.apache.shiro.web.filter.PathMatchingFilter#isEnabled(javax.servlet.ServletRequest, javax.servlet.ServletResponse, String, Object)
     * PathMatchingFilter.isEnabled(request,response,path,pathSpecificConfig)}
     * method if you want to make your enable/disable decision based on any path-specific configuration.
     *
     * @param request the incoming servlet request
     * @param response the outbound servlet response
     * @return {@code true} if this filter should filter the specified request, {@code false} if it should let the
     * request/response pass through immediately to the next element in the {@code FilterChain}.
     * @throws IOException in the case of any IO error
     * @throws ServletException in the case of any error
     * @see org.apache.shiro.web.filter.PathMatchingFilter# isEnabled(javax.servlet.ServletRequest, javax.servlet.ServletResponse, String, Object)
     * @since 1.2
     */
    @SuppressWarnings({"UnusedParameters"})
    protected boolean isEnabled(ServletRequest request, ServletResponse response) throws ServletException, IOException {
        return isEnabled();
    }

    /**
     * Return name of the request attribute that identifies that a request has already been filtered.
     * <p/>
     * The default implementation takes the configured {@link #getName() name} and appends &quot;{@code .FILTERED}&quot;.
     * If the filter is not fully initialized, it falls back to the implementation's class name.
     *
     * @return the name of the request attribute that identifies that a request has already been filtered.
     * @see #getName
     * @see #ALREADY_FILTERED_SUFFIX
     */
    protected String getAlreadyFilteredAttributeName() {
        String name = getName();
        if (name == null) {
            name = getClass().getName();
        }
        return name + ALREADY_FILTERED_SUFFIX;
    }

    /**
     * Can be overridden in subclasses for custom filtering control,
     * returning <code>true</code> to avoid filtering of the given request.
     * <p>The default implementation always returns <code>false</code>.
     *
     * @param request current HTTP request
     * @return whether the given request should <i>not</i> be filtered
     * @throws ServletException in case of errors
     * @deprecated in favor of overriding {@link #isEnabled(javax.servlet.ServletRequest, javax.servlet.ServletResponse)}
     * for custom behavior.  This method will be removed in Shiro 2.0.
     */
    @Deprecated
    @SuppressWarnings({"UnusedDeclaration"})
    protected boolean shouldNotFilter(ServletRequest request) throws ServletException {
        return false;
    }


    /**
     * Same contract as for
     * {@link #doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain)},
     * but guaranteed to be invoked only once per request.
     *
     * @param request  incoming {@code ServletRequest}
     * @param response outgoing {@code ServletResponse}
     * @param chain    the {@code FilterChain} to execute
     * @throws ServletException if there is a problem processing the request
     * @throws IOException      if there is an I/O problem processing the request
     * 抽象方法 交给子类实现
     */
    protected abstract void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
            throws ServletException, IOException;
}
