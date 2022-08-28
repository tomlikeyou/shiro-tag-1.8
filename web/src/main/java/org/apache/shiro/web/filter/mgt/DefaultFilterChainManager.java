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
package org.apache.shiro.web.filter.mgt;

import org.apache.shiro.config.ConfigurationException;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.lang.util.Nameable;
import org.apache.shiro.lang.util.StringUtils;
import org.apache.shiro.web.filter.PathConfigProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Default {@link FilterChainManager} implementation maintaining a map of {@link Filter Filter} instances
 * (key: filter name, value: Filter) as well as a map of {@link NamedFilterList NamedFilterList}s created from these
 * {@code Filter}s (key: filter chain name, value: NamedFilterList).  The {@code NamedFilterList} is essentially a
 * {@link FilterChain} that also has a name property by which it can be looked up.
 *
 * @see NamedFilterList
 * @since 1.0
 * 过滤器链管理器
 */
public class DefaultFilterChainManager implements FilterChainManager {

    private static transient final Logger log = LoggerFactory.getLogger(DefaultFilterChainManager.class);
    /*servlet的 filterConfig信息，在配置filter时候，能够给filter添加一些初始化参数信息，这些初始化参数信息保存在这里，如过滤器名称，servlet上下文，根据名称获取值...*/
    private FilterConfig filterConfig;
    /*保存默认的过滤器信息，以及我们自定义配置的过滤器信息*/
    private Map<String, Filter> filters;
    /*全局的过滤器名称集合*/
    private List<String> globalFilterNames;
    /*配置的url -> authc/anon... 以及 过滤器类型保存在这里*/
    private Map<String, NamedFilterList> filterChains; //key: chain name, value: chain

    /*创建shiro 过滤器链管理器时 会默认加载 DefaultFilter 所有的过滤器添加到filters*/
    public DefaultFilterChainManager() {
        this.filters = new LinkedHashMap<String, Filter>();
        this.filterChains = new LinkedHashMap<String, NamedFilterList>();
        this.globalFilterNames = new ArrayList<>();
        /*添加默认的过滤器到 filters中*/
        addDefaultFilters(false);
    }

    public DefaultFilterChainManager(FilterConfig filterConfig) {
        this.filters = new LinkedHashMap<String, Filter>();
        this.filterChains = new LinkedHashMap<String, NamedFilterList>();
        this.globalFilterNames = new ArrayList<>();
        setFilterConfig(filterConfig);
        addDefaultFilters(true);
    }

    /**
     * Returns the {@code FilterConfig} provided by the Servlet container at webapp startup.
     *
     * @return the {@code FilterConfig} provided by the Servlet container at webapp startup.
     */
    public FilterConfig getFilterConfig() {
        return filterConfig;
    }

    /**
     * Sets the {@code FilterConfig} provided by the Servlet container at webapp startup.
     *
     * @param filterConfig the {@code FilterConfig} provided by the Servlet container at webapp startup.
     */
    public void setFilterConfig(FilterConfig filterConfig) {
        this.filterConfig = filterConfig;
    }

    public Map<String, Filter> getFilters() {
        return filters;
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public void setFilters(Map<String, Filter> filters) {
        this.filters = filters;
    }

    public Map<String, NamedFilterList> getFilterChains() {
        return filterChains;
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public void setFilterChains(Map<String, NamedFilterList> filterChains) {
        this.filterChains = filterChains;
    }

    public Filter getFilter(String name) {
        return this.filters.get(name);
    }

    public void addFilter(String name, Filter filter) {
        addFilter(name, filter, false);
    }

    public void addFilter(String name, Filter filter, boolean init) {
        addFilter(name, filter, init, true);
    }

    public void createDefaultChain(String chainName) {
        /*如果项目没有配置 /** 的拦截规则，shiro默认保存一个/** -> 全局过滤器的 到 filterChains中*/
        if (!getChainNames().contains(chainName) && !CollectionUtils.isEmpty(globalFilterNames)) {
            // add each of global filters
            globalFilterNames.stream().forEach(filterName -> addToChain(chainName, filterName));
        }
    }

    /**
     *
     * @param chainName       url
     * @param chainDefinition 过滤器的名称
     */
    public void createChain(String chainName, String chainDefinition) {
        /*非空判断*/
        if (!StringUtils.hasText(chainName)) {
            throw new NullPointerException("chainName cannot be null or empty.");
        }
        if (!StringUtils.hasText(chainDefinition)) {
            throw new NullPointerException("chainDefinition cannot be null or empty.");
        }
        if (log.isDebugEnabled()) {
            log.debug("Creating chain [" + chainName + "] with global filters " + globalFilterNames + " and from String definition [" + chainDefinition + "]");
        }

        /*首先将全局的过滤器链名称集合里的每一个名称 从filters找到，添加到 我们配置的url 对应的过滤器链中*/
        if (!CollectionUtils.isEmpty(globalFilterNames)) {
            globalFilterNames.stream().forEach(filterName -> addToChain(chainName, filterName));
        }

        //parse the value by tokenizing it to get the resulting filter-specific config entries
        //
        //e.g. for a value of
        //
        //     "authc, roles[admin,user], perms[file:edit]"
        //
        // the resulting token array would equal
        //
        //     { "authc", "roles[admin,user]", "perms[file:edit]" }
        //
        /*对我们配置的url对应的 过滤器类型 进行解析 返回对应的数组*/
        String[] filterTokens = splitChainDefinition(chainDefinition);

        /*将我们配置的url-> authc/anon 的value值，从filters获取对应的filter
         然后保存到url对应的 namedFilterList 中，（因为我们前面已经有了 指定url对应的 namedFilterList）*/
        for (String token : filterTokens) {
            String[] nameConfigPair = toNameConfigPair(token);

            //现在我们有了路径、过滤器名称、（可能为空的）路径特定的配置，保存起来
            addToChain(chainName, nameConfigPair[0], nameConfigPair[1]);
        }
    }

    /**
     * Splits the comma-delimited filter chain definition line into individual filter definition tokens.
     * <p/>
     * Example Input:
     * <pre>
     *     foo, bar[baz], blah[x, y]
     * </pre>
     * Resulting Output:
     * <pre>
     *     output[0] == foo
     *     output[1] == bar[baz]
     *     output[2] == blah[x, y]
     * </pre>
     * @param chainDefinition the comma-delimited filter chain definition.
     * @return an array of filter definition tokens
     * @since 1.2
     * @see <a href="https://issues.apache.org/jira/browse/SHIRO-205">SHIRO-205</a>
     */
    protected String[] splitChainDefinition(String chainDefinition) {
        return StringUtils.split(chainDefinition, StringUtils.DEFAULT_DELIMITER_CHAR, '[', ']', true, true);
    }

    /**
     * Based on the given filter chain definition token (e.g. 'foo' or 'foo[bar, baz]'), this will return the token
     * as a name/value pair, removing any brackets as necessary.  Examples:
     * <table>
     *     <tr>
     *         <th>Input</th>
     *         <th>Result</th>
     *     </tr>
     *     <tr>
     *         <td>{@code foo}</td>
     *         <td>returned[0] == {@code foo}<br/>returned[1] == {@code null}</td>
     *     </tr>
     *     <tr>
     *         <td>{@code foo[bar, baz]}</td>
     *         <td>returned[0] == {@code foo}<br/>returned[1] == {@code bar, baz}</td>
     *     </tr>
     * </table>
     * @param token the filter chain definition token
     * @return A name/value pair representing the filter name and a (possibly null) config value.
     * @throws ConfigurationException if the token cannot be parsed
     * @since 1.2
     * @see <a href="https://issues.apache.org/jira/browse/SHIRO-205">SHIRO-205</a>
     */
    protected String[] toNameConfigPair(String token) throws ConfigurationException {
        /*roles[admin,user]转换后 会变成 roles admin,user*/
        try {
            String[] pair = token.split("\\[", 2);
            String name = StringUtils.clean(pair[0]);

            if (name == null) {
                throw new IllegalArgumentException("Filter name not found for filter chain definition token: " + token);
            }
            String config = null;

            if (pair.length == 2) {
                config = StringUtils.clean(pair[1]);
                //if there was an open bracket, it assumed there is a closing bracket, so strip it too:
                config = config.substring(0, config.length() - 1);
                config = StringUtils.clean(config);

                //backwards compatibility prior to implementing SHIRO-205:
                //prior to SHIRO-205 being implemented, it was common for end-users to quote the config inside brackets
                //if that config required commas.  We need to strip those quotes to get to the interior quoted definition
                //to ensure any existing quoted definitions still function for end users:
                if (config != null && config.startsWith("\"") && config.endsWith("\"")) {
                    String stripped = config.substring(1, config.length() - 1);
                    stripped = StringUtils.clean(stripped);

                    //if the stripped value does not have any internal quotes, we can assume that the entire config was
                    //quoted and we can use the stripped value.
                    if (stripped != null && stripped.indexOf('"') == -1) {
                        config = stripped;
                    }
                    //else:
                    //the remaining config does have internal quotes, so we need to assume that each comma delimited
                    //pair might be quoted, in which case we need the leading and trailing quotes that we stripped
                    //So we ignore the stripped value.
                }
            }
            
            return new String[]{name, config};

        } catch (Exception e) {
            String msg = "Unable to parse filter chain definition token: " + token;
            throw new ConfigurationException(msg, e);
        }
    }

    protected void addFilter(String name, Filter filter, boolean init, boolean overwrite) {
        /*根据名称从filters获取*/
        Filter existing = getFilter(name);
        /*不存在则设置相关属性保存到filters*/
        if (existing == null || overwrite) {
            /*过滤器如果实现了 nameable接口，则设置名称*/
            if (filter instanceof Nameable) {
                ((Nameable) filter).setName(name);
            }
            if (init) {
                initFilter(filter);
            }
            /*保存过滤器信息到 filters，key：DefaultFilter枚举类的名称，value：具体的过滤器实例对象*/
            this.filters.put(name, filter);
        }
    }

    /*
    * 参数1：url
    * 参数2：全局过滤器名称集合 的名称
    * */
    public void addToChain(String chainName, String filterName) {
        addToChain(chainName, filterName, null);
    }

    /*
    * 参数1：url
    * 参数2：全局过滤器名称集合 的名称
    * 参数3：url对应的（可能为空的）配置
    * */
    public void addToChain(String chainName, String filterName, String chainSpecificFilterConfig) {
        /*非空判断*/
        if (!StringUtils.hasText(chainName)) {
            throw new IllegalArgumentException("chainName cannot be null or empty.");
        }
        /*从 filters中 根据过滤器名称 获取对应的过滤器*/
        Filter filter = getFilter(filterName);
        if (filter == null) {
            throw new IllegalArgumentException("There is no filter with name '" + filterName +
                    "' to apply to chain [" + chainName + "] in the pool of available Filters.  Ensure a " +
                    "filter with that name/path has first been registered with the addFilter method(s).");
        }
        /*过滤器保存url 以及url对应的（可能为null）配置*/
        applyChainConfig(chainName, filter, chainSpecificFilterConfig);
        /*返回url对应的 filterList*/
        NamedFilterList chain = ensureChain(chainName);
        /*向url对应的filterList添加一个过滤器*/
        chain.add(filter);
    }

    public void setGlobalFilters(List<String> globalFilterNames) throws ConfigurationException {
        if (!CollectionUtils.isEmpty(globalFilterNames)) {
            for (String filterName : globalFilterNames) {
                Filter filter = filters.get(filterName);
                if (filter == null) {
                    throw new ConfigurationException("There is no filter with name '" + filterName +
                                                     "' to apply to the global filters in the pool of available Filters.  Ensure a " +
                                                     "filter with that name/path has first been registered with the addFilter method(s).");
                }
                /*添加到全局的filter 名称集合里*/
                this.globalFilterNames.add(filterName);
            }
        }
    }

    /**
     *
     * @param chainName url
     * @param filter 对应的过滤器
     * @param chainSpecificFilterConfig url对应的过滤器的配置
     *                                  如配置了这样一个 /userEdit -> role[user,admin] 这样的配置表明该接口 需要user，admin角色才能访问，chainSpecificFilterConfig就是指的是 user,admin
     */
    protected void applyChainConfig(String chainName, Filter filter, String chainSpecificFilterConfig) {
        if (log.isDebugEnabled()) {
            log.debug("Attempting to apply path [" + chainName + "] to filter [" + filter + "] " +
                    "with config [" + chainSpecificFilterConfig + "]");
        }
        /*过滤器如果实现了 PathConfigProcessor接口，调用processPathConfig方法*/
        if (filter instanceof PathConfigProcessor) {
            /*这步表明了 每一个过滤器都保存了需要自己处理的url 以及url 对应的（可能为空）配置，（有的接口需要具体的角色，具体的权限）*/
            ((PathConfigProcessor) filter).processPathConfig(chainName, chainSpecificFilterConfig);
        } else {
            if (StringUtils.hasText(chainSpecificFilterConfig)) {
                //they specified a filter configuration, but the Filter doesn't implement PathConfigProcessor
                //this is an erroneous config:
                String msg = "chainSpecificFilterConfig was specified, but the underlying " +
                        "Filter instance is not an 'instanceof' " +
                        PathConfigProcessor.class.getName() + ".  This is required if the filter is to accept " +
                        "chain-specific configuration.";
                throw new ConfigurationException(msg);
            }
        }
    }

    protected NamedFilterList ensureChain(String chainName) {
        /*根据请求路径从 filterChains集合中获取 filter*/
        NamedFilterList chain = getChain(chainName);
        if (chain == null) {
            /*如果为空，则根据 url创建一个 filterList*/
            chain = new SimpleNamedFilterList(chainName);
            /*将url-> filterList 保存到 filterChains中*/
            this.filterChains.put(chainName, chain);
        }
        return chain;
    }

    public NamedFilterList getChain(String chainName) {
        return this.filterChains.get(chainName);
    }

    public boolean hasChains() {
        return !CollectionUtils.isEmpty(this.filterChains);
    }

    public Set<String> getChainNames() {
        return this.filterChains != null ? this.filterChains.keySet() : Collections.EMPTY_SET;
    }

    /*
    * 参数1：servlet容器的过滤器链
    * 参数2：自定义配置的 匹配的url
    * */
    public FilterChain proxy(FilterChain original, String chainName) {
        /*根据url 名称从filterChains中获取对应的filter集合*/
        NamedFilterList configured = getChain(chainName);
        if (configured == null) {
            String msg = "There is no configured chain under the name/key [" + chainName + "].";
            throw new IllegalArgumentException(msg);
        }
        /*将filterList 包装成 ProxiedFilterChain 返回*/
        return configured.proxy(original);
    }

    /**
     * Initializes the filter by calling <code>filter.init( {@link #getFilterConfig() getFilterConfig()} );</code>.
     *
     * @param filter the filter to initialize with the {@code FilterConfig}.
     */
    protected void initFilter(Filter filter) {
        FilterConfig filterConfig = getFilterConfig();
        if (filterConfig == null) {
            throw new IllegalStateException("FilterConfig attribute has not been set.  This must occur before filter " +
                    "initialization can occur.");
        }
        try {
            filter.init(filterConfig);
        } catch (ServletException e) {
            throw new ConfigurationException(e);
        }
    }

    protected void addDefaultFilters(boolean init) {
        for (DefaultFilter defaultFilter : DefaultFilter.values()) {
            addFilter(defaultFilter.name(), defaultFilter.newInstance(), init, false);
        }
    }
}
