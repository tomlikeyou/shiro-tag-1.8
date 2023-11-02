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

import javax.servlet.*;
import java.io.IOException;
import java.util.List;

/**
 * A proxied filter chain is a {@link FilterChain} instance that proxies an original {@link FilterChain} as well
 * as a {@link List List} of other {@link Filter Filter}s that might need to execute prior to the final wrapped
 * original chain.  It allows a list of filters to execute before continuing the original (proxied)
 * {@code FilterChain} instance.
 *
 * @since 0.9
 * 实现了servlet容器的 过滤器链接口，内部有servlet原始的过滤器链，也有Shiro的过滤器集合
 */
public class ProxiedFilterChain implements FilterChain {
    private static final Logger log = LoggerFactory.getLogger(ProxiedFilterChain.class);

    /**
     * Servlet原始的过滤器链
     */
    private FilterChain orig;
    /**
     * Shiro匹配后的过滤器集合
     */
    private List<Filter> filters;
    private int index = 0;

    /**
     *
     * @param orig servlet原始的过滤器链
     * @param filters shiro的过滤器链
     */
    public ProxiedFilterChain(FilterChain orig, List<Filter> filters) {
        if (orig == null) {
            throw new NullPointerException("original FilterChain cannot be null.");
        }
        /*保存servlet容器原生的 过滤器链*/
        this.orig = orig;
        /*保存shiro 根据url匹配的过滤器链*/
        this.filters = filters;
        this.index = 0;
    }

    public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
        /*条件成立：说明shiro自己的过滤器链 都走完了，需要走servlet自己本身的过滤器链逻辑*/
        if (this.filters == null || this.filters.size() == this.index) {
            //shiro的过滤器链已经执行完了，接下来执行servlet容器原生的过滤器链
            if (log.isTraceEnabled()) {
                log.trace("Invoking original filter chain.");
            }
            /*执行servlet自己的 过滤器链*/
            this.orig.doFilter(request, response);
        } else {
            if (log.isTraceEnabled()) {
                log.trace("Invoking wrapped filter at index [" + this.index + "]");
            }
            /*执行shiro自己封装的 过滤器链*/
            this.filters.get(this.index++).doFilter(request, response, this);
        }
    }
}
