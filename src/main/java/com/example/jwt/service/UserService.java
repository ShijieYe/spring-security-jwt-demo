package com.example.jwt.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.example.jwt.entity.User;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService extends IService<User>, UserDetailsService {

}
