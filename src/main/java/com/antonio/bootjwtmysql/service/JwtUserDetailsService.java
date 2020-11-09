package com.antonio.bootjwtmysql.service;

import com.antonio.bootjwtmysql.model.UserDTO;
import com.antonio.bootjwtmysql.repository.UserRepository;
import com.antonio.bootjwtmysql.model.UserEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

// El servicio que se encarga de pelear contra el repositorio donde
// hacemos la persistencia de los usuarios con sus credenciales.

@Service
public class JwtUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder bcryptEncoder;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserEntity userEntity = userRepository.findByUsername(username);
        if(userEntity == null){
            throw new UsernameNotFoundException("User not found with username: " + username);
        }

        return new User(userEntity.getusername(), userEntity.getPassword(), new ArrayList<>());
    }

    // Almacenamos el usuario con la clave codificada.
    public UserEntity save(UserDTO user) {
        UserEntity newUser = new UserEntity(user.getUsername(), bcryptEncoder.encode(user.getPassword()));
        return userRepository.save(newUser);
    }
}
