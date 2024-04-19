package com.example.jwt.service.Impl;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.example.jwt.entity.User;
import com.example.jwt.mapper.UserMapper;
import com.example.jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 查询用户, 需加判断，用户是否存在，是否被停用，是否已删除等
        // 需把用户权限塞进去 user.setPerms(perms);
        User user = baseMapper.selectOne(new QueryWrapper<User>().lambda()
                .eq(User::getUsername, username));
        if (user == null) return null;
        if (user.getUsername().equals("admin")) {
            user.setPerms(Set.of("admin"));
        } else if (user.getUsername().equals("test")) {
            user.setPerms(Set.of("test"));
        }
        return user;
    }
}
