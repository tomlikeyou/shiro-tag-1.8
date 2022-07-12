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
package org.apache.shiro.web.filter;

import org.apache.shiro.util.AntPathMatcher;
import org.apache.shiro.util.PatternMatcher;
import org.apache.shiro.web.servlet.AdviceFilter;
import org.apache.shiro.web.util.WebUtils;
import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Filter;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.apache.shiro.lang.util.StringUtils.split;

/**
 * <p>Base class for Filters that will process only specified paths and allow all others to pass through.</p>
 * 该过滤器只对配置了url请求拦截的地址进行过滤，其他的url请求直接放行
 * @since 0.9
 */
public abstract class PathMatchingFilter extends AdviceFilter implements PathConfigProcessor {

    private static final Logger log = LoggerFactory.getLogger(PathMatchingFilter.class);

    private static final String DEFAULT_PATH_SEPARATOR = "/";

    /**
     * PatternMatcher used in determining which paths to react to for a given request.
     */
    protected PatternMatcher pathMatcher = new AntPathMatcher();

    /**
     * url->配置 集合，其中键是此过滤器应处理的路径(url)，值是特定于该特定路径(url)的此过滤器的（可能为 null）配置元素
     * 换句话说，键是这个过滤器将处理的路径（url）
     * <p/>
     * 这些值是此过滤器在处理相应键（路径）时应使用的过滤器特定数据。如果没有为该 url 指定过滤器特定的配置，则这些值可以为 null
     * 如 /user/Edit -> role[user,admin]这样的配置 appliedPaths保存的是 key:/user/Edit ;  value: user,admin
     */
    protected Map<String, Object> appliedPaths = new LinkedHashMap<String, Object>();

    /**
     * Splits any comma-delimited values that might be found in the <code>config</code> argument and sets the resulting
     * <code>String[]</code> array on the <code>appliedPaths</code> internal Map.
     * <p/>
     * That is:
     * <pre><code>
     * String[] values = null;
     * if (config != null) {
     *     values = split(config);
     * }
     * <p/>
     * this.{@link #appliedPaths appliedPaths}.put(path, values);
     * </code></pre>
     *
     * @param path   the application context path to match for executing this filter.
     * @param config the specified for <em>this particular filter only</em> for the given <code>path</code>
     * @return this configured filter.
     */
    public Filter processPathConfig(String path, String config) {
        String[] values = null;
        if (config != null) {
            values = split(config);
        }
        /*每个过滤器都会保存自己需要处理的url，以及url对应的（可能为空的）配置信息*/
        this.appliedPaths.put(path, values);
        return this;
    }

    /**
     * Returns the context path within the application based on the specified <code>request</code>.
     * <p/>
     * This implementation merely delegates to
     * {@link WebUtils#getPathWithinApplication(javax.servlet.http.HttpServletRequest) WebUtils.getPathWithinApplication(request)},
     * but can be overridden by subclasses for custom logic.
     *
     * @param request the incoming <code>ServletRequest</code>
     * @return the context path within the application.
     */
    protected String getPathWithinApplication(ServletRequest request) {
        return WebUtils.getPathWithinApplication(WebUtils.toHttp(request));
    }

    /**
     * Returns <code>true</code> if the incoming <code>request</code> matches the specified <code>path</code> pattern,
     * <code>false</code> otherwise.
     * <p/>
     * The default implementation acquires the <code>request</code>'s path within the application and determines
     * if that matches:
     * <p/>
     * <code>String requestURI = {@link #getPathWithinApplication(javax.servlet.ServletRequest) getPathWithinApplication(request)};<br/>
     * return {@link #pathsMatch(String, String) pathsMatch(path,requestURI)}</code>
     *
     * @param path    the configured url pattern to check the incoming request against.
     * @param request the incoming ServletRequest
     * @return <code>true</code> if the incoming <code>request</code> matches the specified <code>path</code> pattern,
     *         <code>false</code> otherwise.
     */
    protected boolean pathsMatch(String path, ServletRequest request) {
        String requestURI = getPathWithinApplication(request);

        log.trace("Attempting to match pattern '{}' with current requestURI '{}'...", path, Encode.forHtml(requestURI));
        boolean match = pathsMatch(path, requestURI);

        if (!match) {
            if (requestURI != null && !DEFAULT_PATH_SEPARATOR.equals(requestURI)
                && requestURI.endsWith(DEFAULT_PATH_SEPARATOR)) {
                requestURI = requestURI.substring(0, requestURI.length() - 1);
            }
            if (path != null && !DEFAULT_PATH_SEPARATOR.equals(path)
                && path.endsWith(DEFAULT_PATH_SEPARATOR)) {
                path = path.substring(0, path.length() - 1);
            }
            log.trace("Attempting to match pattern '{}' with current requestURI '{}'...", path, Encode.forHtml(requestURI));
            match = pathsMatch(path, requestURI);
        }

        return match;
    }

    /**
     * Returns <code>true</code> if the <code>path</code> matches the specified <code>pattern</code> string,
     * <code>false</code> otherwise.
     * <p/>
     * Simply delegates to
     * <b><code>this.pathMatcher.{@link PatternMatcher#matches(String, String) matches(pattern,path)}</code></b>,
     * but can be overridden by subclasses for custom matching behavior.
     *
     * @param pattern the pattern to match against
     * @param path    the value to match with the specified <code>pattern</code>
     * @return <code>true</code> if the <code>path</code> matches the specified <code>pattern</code> string,
     *         <code>false</code> otherwise.
     */
    protected boolean pathsMatch(String pattern, String path) {
        boolean matches = pathMatcher.matches(pattern, path);
        log.trace("Pattern [{}] matches path [{}] => [{}]", pattern, path, matches);
        return matches;
    }

    /**
     * Implementation that handles path-matching behavior before a request is evaluated.  If the path matches and
     * the filter
     * {@link #isEnabled(javax.servlet.ServletRequest, javax.servlet.ServletResponse, String, Object) isEnabled} for
     * that path/config, the request will be allowed through via the result from
     * {@link #onPreHandle(javax.servlet.ServletRequest, javax.servlet.ServletResponse, Object) onPreHandle}.  If the
     * path does not match or the filter is not enabled for that path, this filter will allow passthrough immediately
     * to allow the {@code FilterChain} to continue executing.
     * <p/>
     * In order to retain path-matching functionality, subclasses should not override this method if at all
     * possible, and instead override
     * {@link #onPreHandle(javax.servlet.ServletRequest, javax.servlet.ServletResponse, Object) onPreHandle} instead.
     *
     * @param request  the incoming ServletRequest
     * @param response the outgoing ServletResponse
     * @return {@code true} if the filter chain is allowed to continue to execute, {@code false} if a subclass has
     *         handled the request explicitly.
     * @throws Exception if an error occurs
     */
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        /*如果该过滤器没有需要处理的url请求，则不会对请求进行过滤，返回true让链继续向下执行*/
        if (this.appliedPaths == null || this.appliedPaths.isEmpty()) {
            if (log.isTraceEnabled()) {
                log.trace("appliedPaths property is null or empty.  This Filter will passthrough immediately.");
            }
            return true;
        }

        /*遍历该过滤器要处理的每一个url*/
        for (String path : this.appliedPaths.keySet()) {
            /*如果当前url与当前请求路径匹配，代表该过滤器需要处理该*/
            if (pathsMatch(path, request)) {
                log.trace("Current requestURI matches pattern '{}'.  Determining filter chain execution...", path);
                /*获取该url对应（可能为空）的配置*/
                Object config = this.appliedPaths.get(path);
                /*由该过滤器决定是否让链继续向下执行*/
                return isFilterChainContinued(request, response, path, config);
            }
        }

        //no path matched, allow the request to go through:
        return true;
    }

    /*
    * 参数1：request
    * 参数2：response
    * 参数3：项目配置的url
    * 参数4：项目配置url对应的配置(可能为空)
    * */
    @SuppressWarnings({"JavaDoc"})
    private boolean isFilterChainContinued(ServletRequest request, ServletResponse response,
                                           String path, Object pathConfig) throws Exception {
        /*判断该过滤器是否开启了过滤属性 大多数过滤器都会对任何请求进行过滤执行*/
        if (isEnabled(request, response, path, pathConfig)) { //isEnabled check added in 1.2
            if (log.isTraceEnabled()) {
                log.trace("Filter '{}' is enabled for the current request under path '{}' with config [{}].  " +
                        "Delegating to subclass implementation for 'onPreHandle' check.",
                        new Object[]{getName(), path, pathConfig});
            }
            /*委托给子类实现，以便他们可以决定请求是否应该继续通过链*/
            return onPreHandle(request, response, pathConfig);
        }
        /*走到这里，表明该过滤器并没有开启过滤，不会处理请求; 则直接返回true，让链继续向后走*/
        if (log.isTraceEnabled()) {
            log.trace("Filter '{}' is disabled for the current request under path '{}' with config [{}].  " +
                    "The next element in the FilterChain will be called immediately.",
                    new Object[]{getName(), path, pathConfig});
        }
        return true;
    }

    /*默认返回true，代表对请求不进行拦截处理，继续向后执行*/
    /*参数1：request
    * 参数2：response
    * 参数3：项目配置url对应的配置（可能为空）
    * */
    protected boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        return true;
    }

    /**
     * Path-matching version of the parent class's
     * {@link #isEnabled(javax.servlet.ServletRequest, javax.servlet.ServletResponse)} method, but additionally allows
     * for inspection of any path-specific configuration values corresponding to the specified request.  Subclasses
     * may wish to inspect this additional mapped configuration to determine if the filter is enabled or not.
     * <p/>
     * This method's default implementation ignores the {@code path} and {@code mappedValue} arguments and merely
     * returns the value from a call to {@link #isEnabled(javax.servlet.ServletRequest, javax.servlet.ServletResponse)}.
     * It is expected that subclasses override this method if they need to perform enable/disable logic for a specific
     * request based on any path-specific config for the filter instance.
     *
     * @param request     the incoming servlet request
     * @param response    the outbound servlet response
     * @param path        the path matched for the incoming servlet request that has been configured with the given {@code mappedValue}.
     * @param mappedValue the filter-specific config value mapped to this filter in the URL rules mappings for the given {@code path}.
     * @return {@code true} if this filter should filter the specified request, {@code false} if it should let the
     *         request/response pass through immediately to the next element in the {@code FilterChain}.
     * @throws Exception in the case of any error
     * @since 1.2
     */
    @SuppressWarnings({"UnusedParameters"})
    protected boolean isEnabled(ServletRequest request, ServletResponse response, String path, Object mappedValue)
            throws Exception {
        return isEnabled(request, response);
    }
}
