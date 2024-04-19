package com.example.jwt.controller;

import com.example.jwt.entity.User;
import com.example.jwt.service.SysLoginService;
import com.example.jwt.service.UserService;
import com.example.jwt.util.Result;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/user")
public class UserController2 {
    final SysLoginService loginService;
    final UserService userService;
    final BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();

    @PutMapping("/login")
    public Result login(String username, String password) {
        return Result.success(loginService.login(username, password));
    }

    @PreAuthorize("hasAuthority('admin')")
    @GetMapping("/list")
    public Result list() {
        return Result.success("list");
    }
    @PreAuthorize("hasAnyRole('admin')")
    @PostMapping("/register")
    public Result register(String username, String password) {
        User u = new User();
        u.setUsername(username);
        u.setPassword(bCryptPasswordEncoder.encode(password));
        u.setStatus("0");
        return Result.success(userService.save(u));
    }
}
