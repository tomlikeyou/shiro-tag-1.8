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
package org.apache.shiro.mgt;

import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.subject.support.DelegatingSubject;


/**
 * Default {@link SubjectFactory SubjectFactory} implementation that creates {@link org.apache.shiro.subject.support.DelegatingSubject DelegatingSubject}
 * instances.
 *
 * @since 1.0
 */
public class DefaultSubjectFactory implements SubjectFactory {

    public DefaultSubjectFactory() {
    }

    public Subject createSubject(SubjectContext context) {
        /*从subject上下文中 获取securityManager信息*/
        SecurityManager securityManager = context.resolveSecurityManager();
        /*从subject中获取session信息，可能为null*/
        Session session = context.resolveSession();
        /*从subject中获取 是否开启创建session信息*/
        boolean sessionCreationEnabled = context.isSessionCreationEnabled();
        /*尽可能获取凭据信息，可能为null*/
        PrincipalCollection principals = context.resolvePrincipals();
        /*尽可能获取 是否已认证信息，可能为false*/
        boolean authenticated = context.resolveAuthenticated();
        /*尽可能获取端口信息，可能为空*/
        String host = context.resolveHost();

        return new DelegatingSubject(principals, authenticated, host, session, sessionCreationEnabled, securityManager);
    }

    /**
     * @deprecated since 1.2 - override {@link #createSubject(org.apache.shiro.subject.SubjectContext)} directly if you
     *             need to instantiate a custom {@link Subject} class.
     */
    @Deprecated
    protected Subject newSubjectInstance(PrincipalCollection principals, boolean authenticated, String host,
                                         Session session, SecurityManager securityManager) {
        return new DelegatingSubject(principals, authenticated, host, session, true, securityManager);
    }

}
