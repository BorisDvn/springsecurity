package com.security.springsecurity.service;

import com.security.springsecurity.model.DAOUser;
import com.security.springsecurity.dto.UserDTO;
import com.security.springsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder bcryptEncoder;

    @Override
    //loadUserByEmail
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        List<SimpleGrantedAuthority> roles = null;

        DAOUser user = userRepository.findDAOUserByEmail(email);
        if (user != null) {
            roles = Arrays.asList(new SimpleGrantedAuthority(user.getRole()));
            return new User(user.getEmail(), user.getPassword(), roles);
        }
        throw new UsernameNotFoundException("User not found with the email " + email);
    }

    public DAOUser save(UserDTO user) {
        DAOUser newUser = new DAOUser();
        newUser.setUsername(user.getUsername());
        newUser.setPassword(bcryptEncoder.encode(user.getPassword()));
        newUser.setEmail(user.getEmail());
        newUser.setRole(user.getRole());
        return userRepository.save(newUser);
    }
}
