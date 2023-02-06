package com.example.security1.repository;

import com.example.security1.model.User;
import org.springframework.data.jpa.repository.JpaRepository;


// JpaRepos contains CRUD func.
// can IoC without @Repository due to JpaRepos
public interface UserRepository extends JpaRepository<User, Integer> {
    // findBy/Username << select * from user where username = 1?
    public User findByUsername(String username); // Jpa Query methods

}
