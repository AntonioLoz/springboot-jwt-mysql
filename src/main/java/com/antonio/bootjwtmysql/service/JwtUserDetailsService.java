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

/**
 *
 * Esta clase hara de servicio de UserDetails. Implementará UserDetailsService y
 * sobreescribiremos el metodo loadUserByUsername(String username) e implementaremos
 * un metodo save(UserDTO user), el cual será usado para
 */

@Service
public class JwtUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder bcryptEncoder;


    // En este metodo puede cargar el usuario con el username que le paso por parametro
    // desde el repositorio. Una vez tenga el usuario, al objeto de la clase UserDetails
    // que retornamos, solo le añadiremos los datos de seguridad necesario (username,
    // password, roles). Los demás datos los cargaremos despues de hacer la autenticacion,
    // mediante una petición que nos hará el cliente una vez tenga el token.
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