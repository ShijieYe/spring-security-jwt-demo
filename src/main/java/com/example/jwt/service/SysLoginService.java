package com.example.jwt.service;

import com.example.jwt.exception.BaseException;
import com.example.jwt.exception.UserPasswordNotMatchException;
import com.example.jwt.util.JwtTokenUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

/**
 * 登录校验方法
 *
 * @author tduck
 */
@Component
@RequiredArgsConstructor
public class SysLoginService {

    private final AuthenticationManager authenticationManager;

    private final JwtTokenUtil jwtTokenUtil;

    /**
     * 登录验证
     *
     * @param username 用户名
     * @param password 密码
     * @return 结果
     */
    public String login(String username, String password) {
        // 用户验证
        Authentication authentication = null;
        try {
            // 该方法会去调用UserDetailsServiceImpl.loadUserByUsername
            authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (BadCredentialsException e) {
            throw new UserPasswordNotMatchException("用户不存在/密码错误");
        } catch (BaseException e) {
            throw new BaseException(e.getMessage());
        }
        // 生成token
        return jwtTokenUtil.generateToken(username);
    }

}
