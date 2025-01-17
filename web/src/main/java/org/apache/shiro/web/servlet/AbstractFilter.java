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

import org.apache.shiro.lang.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Filter;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;

/**
 * Base abstract Filter simplifying Filter initialization and {@link #getInitParam(String) access} to init parameters.
 * Subclass initialization logic should be performed by overriding the {@link #onFilterConfigSet()} template method.
 * FilterChain execution logic (the
 * {@link #doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain)} method
 * is left to subclasses.
 *
 * @since 1.0
 * 实现了servlet的filter过滤器接口
 */
public abstract class AbstractFilter extends ServletContextSupport implements Filter {

    private static transient final Logger log = LoggerFactory.getLogger(AbstractFilter.class);

    /**
     * Servlet容器在启动时提供的 过滤器配置
     */
    protected FilterConfig filterConfig;

    /**
     * 过滤器配置
     */
    public FilterConfig getFilterConfig() {
        return filterConfig;
    }

    /**
     * Sets the FilterConfig <em>and</em> the {@code ServletContext} as attributes of this class for use by
     * subclasses.  That is:
     * <pre>
     * this.filterConfig = filterConfig;
     * setServletContext(filterConfig.getServletContext());</pre>
     *
     * @param filterConfig the FilterConfig instance provided by the Servlet container at start-up.
     */
    public void setFilterConfig(FilterConfig filterConfig) {
        /*保存servlet 过滤器配置*/
        this.filterConfig = filterConfig;
        /*保存servlet上下文到 ServletContextSupport中*/
        setServletContext(filterConfig.getServletContext());
    }

    /**
     * Returns the value for the named {@code init-param}, or {@code null} if there was no {@code init-param}
     * specified by that name.
     *
     * @param paramName the name of the {@code init-param}
     * @return the value for the named {@code init-param}, or {@code null} if there was no {@code init-param}
     *         specified by that name.
     *  从filterConfig中获取属性，不存在返回null
     */
    protected String getInitParam(String paramName) {
        FilterConfig config = getFilterConfig();
        if (config != null) {
            return StringUtils.clean(config.getInitParameter(paramName));
        }
        return null;
    }

    /**
     * Sets the filter's {@link #setFilterConfig filterConfig} and then immediately calls
     * {@link #onFilterConfigSet() onFilterConfigSet()} to trigger any processing a subclass might wish to perform.
     *
     * @param filterConfig the servlet container supplied FilterConfig instance.
     * @throws javax.servlet.ServletException if {@link #onFilterConfigSet() onFilterConfigSet()} throws an Exception.
     */
    public final void init(FilterConfig filterConfig) throws ServletException {
        /*保存过滤器配置 以及 servlet上下文*/
        setFilterConfig(filterConfig);
        try {
            /*子类拓展*/
            onFilterConfigSet();
        } catch (Exception e) {
            if (e instanceof ServletException) {
                throw (ServletException) e;
            } else {
                if (log.isErrorEnabled()) {
                    log.error("Unable to start Filter: [" + e.getMessage() + "].", e);
                }
                throw new ServletException(e);
            }
        }
    }

    /**
     * Template method to be overridden by subclasses to perform initialization logic at start-up.  The
     * {@code ServletContext} and {@code FilterConfig} will be accessible
     * (and non-{@code null}) at the time this method is invoked via the
     * {@link #getServletContext() getServletContext()} and {@link #getFilterConfig() getFilterConfig()}
     * methods respectively.
     * <p/>
     * {@code init-param} values may be conveniently obtained via the {@link #getInitParam(String)} method.
     *
     * @throws Exception if the subclass has an error upon initialization.
     * 子类拓展点
     */
    protected void onFilterConfigSet() throws Exception {
    }

    /**
     * Default no-op implementation that can be overridden by subclasses for custom cleanup behavior.
     */
    public void destroy() {
    }


}