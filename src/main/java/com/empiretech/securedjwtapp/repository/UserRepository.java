package com.empiretech.securedjwtapp.repository;

import com.empiretech.securedjwtapp.entity.User;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Integer> {

    User findByUserName(String username);
    
}
