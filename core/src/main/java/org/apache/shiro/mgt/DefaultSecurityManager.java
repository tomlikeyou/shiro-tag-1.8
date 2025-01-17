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

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.Authenticator;
import org.apache.shiro.authc.LogoutAware;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.DefaultSessionContext;
import org.apache.shiro.session.mgt.DefaultSessionKey;
import org.apache.shiro.session.mgt.SessionContext;
import org.apache.shiro.session.mgt.SessionKey;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.apache.shiro.util.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.Collection;

/**
 * The Shiro framework's default concrete implementation of the {@link SecurityManager} interface,
 * based around a collection of {@link org.apache.shiro.realm.Realm}s.  This implementation delegates its
 * authentication, authorization, and session operations to wrapped {@link Authenticator}, {@link Authorizer}, and
 * {@link org.apache.shiro.session.mgt.SessionManager SessionManager} instances respectively via superclass
 * implementation.
 * <p/>
 * To greatly reduce and simplify configuration, this implementation (and its superclasses) will
 * create suitable defaults for all of its required dependencies, <em>except</em> the required one or more
 * {@link Realm Realm}s.  Because {@code Realm} implementations usually interact with an application's data model,
 * they are almost always application specific;  you will want to specify at least one custom
 * {@code Realm} implementation that 'knows' about your application's data/security model
 * (via {@link #setRealm} or one of the overloaded constructors).  All other attributes in this class hierarchy
 * will have suitable defaults for most enterprise applications.
 * <p/>
 * <b>RememberMe notice</b>: This class supports the ability to configure a
 * {@link #setRememberMeManager RememberMeManager}
 * for {@code RememberMe} identity services for login/logout, BUT, a default instance <em>will not</em> be created
 * for this attribute at startup.
 * <p/>
 * Because RememberMe services are inherently client tier-specific and
 * therefore application-dependent, if you want {@code RememberMe} services enabled, you will have to specify an
 * instance yourself via the {@link #setRememberMeManager(RememberMeManager) setRememberMeManager}
 * mutator.  However if you're reading this JavaDoc with the
 * expectation of operating in a Web environment, take a look at the
 * {@code org.apache.shiro.web.DefaultWebSecurityManager} implementation, which
 * <em>does</em> support {@code RememberMe} services by default at startup.
 *
 * @since 0.2
 */
public class DefaultSecurityManager extends SessionsSecurityManager {

    private static final Logger log = LoggerFactory.getLogger(DefaultSecurityManager.class);

    protected RememberMeManager rememberMeManager;
    protected SubjectDAO subjectDAO;
    protected SubjectFactory subjectFactory;

    /**
     * Default no-arg constructor.
     */
    public DefaultSecurityManager() {
        super();
        /*设置默认的 subjectFactory*/
        this.subjectFactory = new DefaultSubjectFactory();
        /*设置默认的 subjectDao*/
        this.subjectDAO = new DefaultSubjectDAO();
    }

    /**
     * Supporting constructor for a single-realm application.
     *
     * @param singleRealm the single realm used by this SecurityManager.
     */
    public DefaultSecurityManager(Realm singleRealm) {
        this();
        setRealm(singleRealm);
    }

    /**
     * Supporting constructor for multiple {@link #setRealms realms}.
     *
     * @param realms the realm instances backing this SecurityManager.
     */
    public DefaultSecurityManager(Collection<Realm> realms) {
        this();
        setRealms(realms);
    }

    /**
     * Returns the {@code SubjectFactory} responsible for creating {@link Subject} instances exposed to the application.
     *
     * @return the {@code SubjectFactory} responsible for creating {@link Subject} instances exposed to the application.
     */
    public SubjectFactory getSubjectFactory() {
        return subjectFactory;
    }

    /**
     * Sets the {@code SubjectFactory} responsible for creating {@link Subject} instances exposed to the application.
     *
     * @param subjectFactory the {@code SubjectFactory} responsible for creating {@link Subject} instances exposed to the application.
     */
    public void setSubjectFactory(SubjectFactory subjectFactory) {
        this.subjectFactory = subjectFactory;
    }

    /**
     * Returns the {@code SubjectDAO} responsible for persisting Subject state, typically used after login or when an
     * Subject identity is discovered (e.g. after RememberMe services).  Unless configured otherwise, the default
     * implementation is a {@link DefaultSubjectDAO}.
     *
     * @return the {@code SubjectDAO} responsible for persisting Subject state, typically used after login or when an
     *         Subject identity is discovered (e.g. after RememberMe services).
     * @see DefaultSubjectDAO
     * @since 1.2
     */
    public SubjectDAO getSubjectDAO() {
        return subjectDAO;
    }

    /**
     * Sets the {@code SubjectDAO} responsible for persisting Subject state, typically used after login or when an
     * Subject identity is discovered (e.g. after RememberMe services). Unless configured otherwise, the default
     * implementation is a {@link DefaultSubjectDAO}.
     *
     * @param subjectDAO the {@code SubjectDAO} responsible for persisting Subject state, typically used after login or when an
     *                   Subject identity is discovered (e.g. after RememberMe services).
     * @see DefaultSubjectDAO
     * @since 1.2
     */
    public void setSubjectDAO(SubjectDAO subjectDAO) {
        this.subjectDAO = subjectDAO;
    }

    public RememberMeManager getRememberMeManager() {
        return rememberMeManager;
    }

    public void setRememberMeManager(RememberMeManager rememberMeManager) {
        this.rememberMeManager = rememberMeManager;
    }

    protected SubjectContext createSubjectContext() {
        return new DefaultSubjectContext();
    }

    /**
     * Creates a {@code Subject} instance for the user represented by the given method arguments.
     *
     * @param token    the {@code AuthenticationToken} submitted for the successful authentication.
     * @param info     the {@code AuthenticationInfo} of a newly authenticated user.
     * @param existing the existing {@code Subject} instance that initiated the authentication attempt
     * @return the {@code Subject} instance that represents the context and session data for the newly
     *         authenticated subject.
     */
    protected Subject createSubject(AuthenticationToken token, AuthenticationInfo info, Subject existing) {
        /*实例化一个subject上下文*/
        SubjectContext context = createSubjectContext();
        /*subject上下文设置 认证属性为true*/
        context.setAuthenticated(true);
        /*subject上下文保存 AuthenticationToken信息*/
        context.setAuthenticationToken(token);
        /*subject上下文保存 AuthenticationInfo信息*/
        context.setAuthenticationInfo(info);
        /*subject上下文保存 安全管理器信息*/
        context.setSecurityManager(this);
        /*保存subject信息*/
        if (existing != null) {
            context.setSubject(existing);
        }
        /*根据subject上下文信息实例化一个subject*/
        return createSubject(context);
    }

    /**
     * Binds a {@code Subject} instance created after authentication to the application for later use.
     * <p/>
     * As of Shiro 1.2, this method has been deprecated in favor of {@link #save(org.apache.shiro.subject.Subject)},
     * which this implementation now calls.
     *
     * @param subject the {@code Subject} instance created after authentication to be bound to the application
     *                for later use.
     * @see #save(org.apache.shiro.subject.Subject)
     * @deprecated in favor of {@link #save(org.apache.shiro.subject.Subject) save(subject)}.
     */
    @Deprecated
    protected void bind(Subject subject) {
        save(subject);
    }

    protected void rememberMeSuccessfulLogin(AuthenticationToken token, AuthenticationInfo info, Subject subject) {
        RememberMeManager rmm = getRememberMeManager();
        if (rmm != null) {
            try {
                rmm.onSuccessfulLogin(subject, token, info);
            } catch (Exception e) {
                if (log.isWarnEnabled()) {
                    String msg = "Delegate RememberMeManager instance of type [" + rmm.getClass().getName() +
                            "] threw an exception during onSuccessfulLogin.  RememberMe services will not be " +
                            "performed for account [" + info + "].";
                    log.warn(msg, e);
                }
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("This " + getClass().getName() + " instance does not have a " +
                        "[" + RememberMeManager.class.getName() + "] instance configured.  RememberMe services " +
                        "will not be performed for account [" + info + "].");
            }
        }
    }

    protected void rememberMeFailedLogin(AuthenticationToken token, AuthenticationException ex, Subject subject) {
        RememberMeManager rmm = getRememberMeManager();
        if (rmm != null) {
            try {
                rmm.onFailedLogin(subject, token, ex);
            } catch (Exception e) {
                if (log.isWarnEnabled()) {
                    String msg = "Delegate RememberMeManager instance of type [" + rmm.getClass().getName() +
                            "] threw an exception during onFailedLogin for AuthenticationToken [" +
                            token + "].";
                    log.warn(msg, e);
                }
            }
        }
    }

    protected void rememberMeLogout(Subject subject) {
        RememberMeManager rmm = getRememberMeManager();
        if (rmm != null) {
            try {
                rmm.onLogout(subject);
            } catch (Exception e) {
                if (log.isWarnEnabled()) {
                    String msg = "Delegate RememberMeManager instance of type [" + rmm.getClass().getName() +
                            "] threw an exception during onLogout for subject with principals [" +
                            (subject != null ? subject.getPrincipals() : null) + "]";
                    log.warn(msg, e);
                }
            }
        }
    }

    /**
     * First authenticates the {@code AuthenticationToken} argument, and if successful, constructs a
     * {@code Subject} instance representing the authenticated account's identity.
     * <p/>
     * Once constructed, the {@code Subject} instance is then {@link #bind bound} to the application for
     * subsequent access before being returned to the caller.
     *
     * @param token the authenticationToken to process for the login attempt.
     * @return a Subject representing the authenticated user.
     * @throws AuthenticationException if there is a problem authenticating the specified {@code token}.
     */
    public Subject login(Subject subject, AuthenticationToken token) throws AuthenticationException {
        AuthenticationInfo info;
        try {
            info = authenticate(token);
        } catch (AuthenticationException ae) {
            try {
                onFailedLogin(token, ae, subject);
            } catch (Exception e) {
                if (log.isInfoEnabled()) {
                    log.info("onFailedLogin method threw an " +
                            "exception.  Logging and propagating original AuthenticationException.", e);
                }
            }
            throw ae; //propagate
        }
        /*
        * 保存相关信息 然后实例化一个新的subject
        * 参数1：token信息
        * 参数2：认证info信息
        * 参数3：threadLocal里的subject，暂称之为旧的 subject 或者称之为真实暴露给用户的subject
        * */
        Subject loggedIn = createSubject(token, info, subject);

        onSuccessfulLogin(token, info, loggedIn);

        return loggedIn;
    }

    protected void onSuccessfulLogin(AuthenticationToken token, AuthenticationInfo info, Subject subject) {
        rememberMeSuccessfulLogin(token, info, subject);
    }

    protected void onFailedLogin(AuthenticationToken token, AuthenticationException ae, Subject subject) {
        rememberMeFailedLogin(token, ae, subject);
    }

    protected void beforeLogout(Subject subject) {
        rememberMeLogout(subject);
    }

    protected SubjectContext copy(SubjectContext subjectContext) {
        return new DefaultSubjectContext(subjectContext);
    }

    /**
     * This implementation functions as follows:
     * <p/>
     * <ol>
     * <li>Ensures the {@code SubjectContext} is as populated as it can be, using heuristics to acquire
     * data that may not have already been available to it (such as a referenced session or remembered principals).</li>
     * <li>Calls {@link #doCreateSubject(org.apache.shiro.subject.SubjectContext)} to actually perform the
     * {@code Subject} instance creation.</li>
     * <li>calls {@link #save(org.apache.shiro.subject.Subject) save(subject)} to ensure the constructed
     * {@code Subject}'s state is accessible for future requests/invocations if necessary.</li>
     * <li>returns the constructed {@code Subject} instance.</li>
     * </ol>
     *
     * @param subjectContext any data needed to direct how the Subject should be constructed.
     * @return the {@code Subject} instance reflecting the specified contextual data.
     * @see #ensureSecurityManager(org.apache.shiro.subject.SubjectContext)
     * @see #resolveSession(org.apache.shiro.subject.SubjectContext)
     * @see #resolvePrincipals(org.apache.shiro.subject.SubjectContext)
     * @see #doCreateSubject(org.apache.shiro.subject.SubjectContext)
     * @see #save(org.apache.shiro.subject.Subject)
     * @since 1.0
     * 根据subject上下文实例化一个subject
     */
    public Subject createSubject(SubjectContext subjectContext) {
        //创建一个subject上下文副本，这样我们就不会修改参数的支持映射
        SubjectContext context = copy(subjectContext);

        //确保上下文有一个 SecurityManager 实例，如果没有，则将当前的安全管理器 添加进去
        context = ensureSecurityManager(context);

        /*确保subject上下文有一个session，第一次请求过来时候，subject是没有session信息的，
        刚认证通过之后走这里也是获取不到的，因为是从threadLocal保存的subject获取的
        认证之后后面的接口请求，这里是能够获取到session信息的，从浏览器cookie中获取到sessionId，然后从sessionDao中获取到session
        */
        context = resolveSession(context);

        /*确保subject上下文有Principals信息，同样 第一次请求过来时候，subject是没有 Principals 信息的*/
        context = resolvePrincipals(context);
        /*第一次实例化的subject只有 安全管理器、request、response信息、authenticated=false、sessionEnabled=true这些信息*/
        /*认证通过之后，subject里有安全管理器、request、response、sessionEnabled=true、authenticated=true、principals */
        Subject subject = doCreateSubject(context);

        //save this subject for future reference if necessary:
        //(this is needed here in case rememberMe principals were resolved and they need to be stored in the
        //session, so we don't constantly rehydrate the rememberMe PrincipalCollection on every operation).
        //Added in 1.2:
        save(subject);

        return subject;
    }

    /**
     * Actually creates a {@code Subject} instance by delegating to the internal
     * {@link #getSubjectFactory() subjectFactory}.  By the time this method is invoked, all possible
     * {@code SubjectContext} data (session, principals, et al.) has been made accessible using all known heuristics
     * and will be accessible to the {@code subjectFactory} via the {@code subjectContext.resolve*} methods.
     *
     * @param context the populated context (data map) to be used by the {@code SubjectFactory} when creating a
     *                {@code Subject} instance.
     * @return a {@code Subject} instance reflecting the data in the specified {@code SubjectContext} data map.
     * @see #getSubjectFactory()
     * @see SubjectFactory#createSubject(org.apache.shiro.subject.SubjectContext)
     * @since 1.2
     */
    protected Subject doCreateSubject(SubjectContext context) {
        return getSubjectFactory().createSubject(context);
    }

    /**
     * Saves the subject's state to a persistent location for future reference if necessary.
     * <p/>
     * This implementation merely delegates to the internal {@link #setSubjectDAO(SubjectDAO) subjectDAO} and calls
     * {@link SubjectDAO#save(org.apache.shiro.subject.Subject) subjectDAO.save(subject)}.
     *
     * @param subject the subject for which state will potentially be persisted
     * @see SubjectDAO#save(org.apache.shiro.subject.Subject)
     * @since 1.2
     */
    protected void save(Subject subject) {
        this.subjectDAO.save(subject);
    }

    /**
     * Removes (or 'unbinds') the Subject's state from the application, typically called during {@link #logout}..
     * <p/>
     * This implementation merely delegates to the internal {@link #setSubjectDAO(SubjectDAO) subjectDAO} and calls
     * {@link SubjectDAO#delete(org.apache.shiro.subject.Subject) delete(subject)}.
     *
     * @param subject the subject for which state will be removed
     * @see SubjectDAO#delete(org.apache.shiro.subject.Subject)
     * @since 1.2
     */
    protected void delete(Subject subject) {
        this.subjectDAO.delete(subject);
    }

    /**
     * Determines if there is a {@code SecurityManager} instance in the context, and if not, adds 'this' to the
     * context.  This ensures the SubjectFactory instance will have access to a SecurityManager during Subject
     * construction if necessary.
     *
     * @param context the subject context data that may contain a SecurityManager instance.
     * @return The SubjectContext to use to pass to a {@link SubjectFactory} for subject creation.
     * @since 1.0
     */
    @SuppressWarnings({"unchecked"})
    protected SubjectContext ensureSecurityManager(SubjectContext context) {
        if (context.resolveSecurityManager() != null) {
            log.trace("Context already contains a SecurityManager instance.  Returning.");
            return context;
        }
        log.trace("No SecurityManager found in context.  Adding self reference.");
        context.setSecurityManager(this);
        return context;
    }

    /**
     * Attempts to resolve any associated session based on the context and returns a
     * context that represents this resolved {@code Session} to ensure it may be referenced if necessary by the
     * invoked {@link SubjectFactory} that performs actual {@link Subject} construction.
     * <p/>
     * If there is a {@code Session} already in the context because that is what the caller wants to be used for
     * {@code Subject} construction, or if no session is resolved, this method effectively does nothing
     * returns the context method argument unaltered.
     *
     * @param context the subject context data that may resolve a Session instance.
     * @return The context to use to pass to a {@link SubjectFactory} for subject creation.
     * @since 1.0
     */
    @SuppressWarnings({"unchecked"})
    protected SubjectContext resolveSession(SubjectContext context) {
        /*尝试从subject 上下文中获取session*/
        if (context.resolveSession() != null) {
            log.debug("Context already contains a session.  Returning.");
            return context;
        }
        try {
            //subject上下文无法直接解决它，让我们看看是否可以，因为我们可以直接访问会话管理器
            Session session = resolveContextSession(context);
            /*如果从会话管理器中获取到了session信息，则subject上下文保存起来session信息*/
            if (session != null) {
                /*这里的session是一个delegatingSession信息*/
                context.setSession(session);
            }
        } catch (InvalidSessionException e) {
            log.debug("Resolved SubjectContext context session is invalid.  Ignoring and creating an anonymous " +
                    "(session-less) Subject instance.", e);
        }
        return context;
    }

    protected Session resolveContextSession(SubjectContext context) throws InvalidSessionException {
        SessionKey key = getSessionKey(context);
        if (key != null) {
            return getSession(key);
        }
        return null;
    }

    protected SessionKey getSessionKey(SubjectContext context) {
        Serializable sessionId = context.getSessionId();
        if (sessionId != null) {
            return new DefaultSessionKey(sessionId);
        }
        return null;
    }

    private static boolean isEmpty(PrincipalCollection pc) {
        return pc == null || pc.isEmpty();
    }

    /**
     * Attempts to resolve an identity (a {@link PrincipalCollection}) for the context using heuristics.  This
     * implementation functions as follows:
     * <ol>
     * <li>Check the context to see if it can already {@link SubjectContext#resolvePrincipals resolve an identity}.  If
     * so, this method does nothing and returns the method argument unaltered.</li>
     * <li>Check for a RememberMe identity by calling {@link #getRememberedIdentity}.  If that method returns a
     * non-null value, place the remembered {@link PrincipalCollection} in the context.</li>
     * </ol>
     *
     * @param context the subject context data that may provide (directly or indirectly through one of its values) a
     *                {@link PrincipalCollection} identity.
     * @return The Subject context to use to pass to a {@link SubjectFactory} for subject creation.
     * @since 1.0
     */
    @SuppressWarnings({"unchecked"})
    protected SubjectContext resolvePrincipals(SubjectContext context) {
        /*认证之后，后面的接口 principals是从session里获取的，从sessionDao获取到了session，然后从session里获取 principals信息*/
        PrincipalCollection principals = context.resolvePrincipals();

        if (isEmpty(principals)) {
            log.trace("No identity (PrincipalCollection) found in the context.  Looking for a remembered identity.");

            principals = getRememberedIdentity(context);

            if (!isEmpty(principals)) {
                log.debug("Found remembered PrincipalCollection.  Adding to the context to be used " +
                        "for subject construction by the SubjectFactory.");

                context.setPrincipals(principals);

                // The following call was removed (commented out) in Shiro 1.2 because it uses the session as an
                // implementation strategy.  Session use for Shiro's own needs should be controlled in a single place
                // to be more manageable for end-users: there are a number of stateless (e.g. REST) applications that
                // use Shiro that need to ensure that sessions are only used when desirable.  If Shiro's internal
                // implementations used Subject sessions (setting attributes) whenever we wanted, it would be much
                // harder for end-users to control when/where that occurs.
                //
                // Because of this, the SubjectDAO was created as the single point of control, and session state logic
                // has been moved to the DefaultSubjectDAO implementation.

                // Removed in Shiro 1.2.  SHIRO-157 is still satisfied by the new DefaultSubjectDAO implementation
                // introduced in 1.2
                // Satisfies SHIRO-157:
                // bindPrincipalsToSession(principals, context);

            } else {
                log.trace("No remembered identity found.  Returning original context.");
            }
        }

        return context;
    }

    protected SessionContext createSessionContext(SubjectContext subjectContext) {
        DefaultSessionContext sessionContext = new DefaultSessionContext();
        if (!CollectionUtils.isEmpty(subjectContext)) {
            sessionContext.putAll(subjectContext);
        }
        Serializable sessionId = subjectContext.getSessionId();
        if (sessionId != null) {
            sessionContext.setSessionId(sessionId);
        }
        String host = subjectContext.resolveHost();
        if (host != null) {
            sessionContext.setHost(host);
        }
        return sessionContext;
    }

    public void logout(Subject subject) {

        if (subject == null) {
            throw new IllegalArgumentException("Subject method argument cannot be null.");
        }

        beforeLogout(subject);

        PrincipalCollection principals = subject.getPrincipals();
        if (principals != null && !principals.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("Logging out subject with primary principal {}", principals.getPrimaryPrincipal());
            }
            Authenticator authc = getAuthenticator();
            if (authc instanceof LogoutAware) {
                ((LogoutAware) authc).onLogout(principals);
            }
        }

        try {
            delete(subject);
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                String msg = "Unable to cleanly unbind Subject.  Ignoring (logging out).";
                log.debug(msg, e);
            }
        } finally {
            try {
                stopSession(subject);
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    String msg = "Unable to cleanly stop Session for Subject [" + subject.getPrincipal() + "] " +
                            "Ignoring (logging out).";
                    log.debug(msg, e);
                }
            }
        }
    }

    protected void stopSession(Subject subject) {
        Session s = subject.getSession(false);
        if (s != null) {
            s.stop();
        }
    }

    /**
     * Unbinds or removes the Subject's state from the application, typically called during {@link #logout}.
     * <p/>
     * This has been deprecated in Shiro 1.2 in favor of the {@link #delete(org.apache.shiro.subject.Subject) delete}
     * method.  The implementation has been updated to invoke that method.
     *
     * @param subject the subject to unbind from the application as it will no longer be used.
     * @deprecated in Shiro 1.2 in favor of {@link #delete(org.apache.shiro.subject.Subject)}
     */
    @Deprecated
    @SuppressWarnings({"UnusedDeclaration"})
    protected void unbind(Subject subject) {
        delete(subject);
    }

    protected PrincipalCollection getRememberedIdentity(SubjectContext subjectContext) {
        RememberMeManager rmm = getRememberMeManager();
        if (rmm != null) {
            try {
                return rmm.getRememberedPrincipals(subjectContext);
            } catch (Exception e) {
                if (log.isWarnEnabled()) {
                    String msg = "Delegate RememberMeManager instance of type [" + rmm.getClass().getName() +
                            "] threw an exception during getRememberedPrincipals().";
                    log.warn(msg, e);
                }
            }
        }
        return null;
    }
}
