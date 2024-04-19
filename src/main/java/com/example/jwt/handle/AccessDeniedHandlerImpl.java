package com.example.jwt.handle;

import com.example.jwt.util.ResponseUtils;
import com.example.jwt.util.Result;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class AccessDeniedHandlerImpl implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e)
            throws IOException, ServletException {
        // 返回 403
        ResponseUtils.outJson(response, Result.failed(HttpStatus.FORBIDDEN.value(), "权限不足，请联系管理员"));
    }

}
