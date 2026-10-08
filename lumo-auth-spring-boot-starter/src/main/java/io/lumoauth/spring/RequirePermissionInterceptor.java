package io.lumoauth.spring;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.security.access.AccessDeniedException;

import java.lang.reflect.Method;
import java.util.Arrays;

/** Enforces {@link RequirePermission} on proxied bean methods. */
public class RequirePermissionInterceptor implements MethodInterceptor {

    private final LumoAuthorization authorization;

    public RequirePermissionInterceptor(LumoAuthorization authorization) {
        this.authorization = authorization;
    }

    @Override
    public Object invoke(MethodInvocation invocation) throws Throwable {
        RequirePermission required = find(invocation.getMethod(), invocation.getThis());
        if (required != null && !authorization.satisfies(Arrays.asList(required.value()), required.mode())) {
            throw new AccessDeniedException("Missing permission: " + String.join(", ", required.value()));
        }
        return invocation.proceed();
    }

    static RequirePermission find(Method method, Object target) {
        RequirePermission onMethod = AnnotatedElementUtils.findMergedAnnotation(method, RequirePermission.class);
        if (onMethod != null) {
            return onMethod;
        }
        Class<?> type = target != null ? org.springframework.aop.support.AopUtils.getTargetClass(target) : method.getDeclaringClass();
        return AnnotatedElementUtils.findMergedAnnotation(type, RequirePermission.class);
    }
}
