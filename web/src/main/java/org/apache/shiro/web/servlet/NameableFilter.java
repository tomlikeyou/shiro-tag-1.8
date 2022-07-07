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

import org.apache.shiro.lang.util.Nameable;

import javax.servlet.FilterConfig;

/**
 * 允许通过setName方法命名过滤器。
 * 如果没有指定名称，过滤器的名称将默认为 {@code web.xml} 中给的名称（配置过滤器时候的filter-name的值）
 *
 * @since 1.0
 */
public abstract class NameableFilter extends AbstractFilter implements Nameable {

    /**
     *过滤器的名称，在应用程序中是唯一的
     */
    private String name;

    /**
     * 获取过滤器名称，如果没有则从过滤器配置中获取过滤器名称
     * @return
     */
    protected String getName() {
        if (this.name == null) {
            FilterConfig config = getFilterConfig();
            if (config != null) {
                this.name = config.getFilterName();
            }
        }

        return this.name;
    }

    /**
     * 设置过滤器名称
     */
    public void setName(String name) {
        this.name = name;
    }

    protected StringBuilder toStringBuilder() {
        String name = getName();
        if (name == null) {
            return super.toStringBuilder();
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append(name);
            return sb;
        }
    }

}
