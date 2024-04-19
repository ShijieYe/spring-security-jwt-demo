package com.example.jwt.handle;

import com.example.jwt.util.ResponseUtils;
import com.example.jwt.util.Result;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.Serializable;

/**
 * 认证失败处理类 返回未授权
 *
 * @author smalljop
 */
@Component
public class AuthenticationEntryPointImpl implements AuthenticationEntryPoint, Serializable {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) {
        ResponseUtils.outHttpJson(response, Result.failed(HttpStatus.UNAUTHORIZED.value(), "认证失败，无法访问系统资源！"));
    }
}
