package com.antonio.bootjwtmysql.controller;

import com.antonio.bootjwtmysql.config.JwtTokenUtil;
import com.antonio.bootjwtmysql.model.JwtRequest;
import com.antonio.bootjwtmysql.model.JwtResponse;
import com.antonio.bootjwtmysql.model.UserDTO;
import com.antonio.bootjwtmysql.service.JwtUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

// Esta clase será el controlador de las autenticaciones. Se encarga de
// comprobar si las credenciales son correctas, a partir de aqui
// generará el token de autenticacion, almacenar nuevos usuarios
@RestController
@CrossOrigin
public class JwtAuthenticationController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenUtil tokenUtil;

    @Autowired
    private JwtUserDetailsService userDetailsService;

    // Aqui recogemos las credenciales de autenticacion enviadas por el cliente.
    // las autenticamos con la llamada al metodo authenticate()
    // cargamos los detalles de usuario atraves del nombre de usuario y
    // generamos el token a devolver.
    @PostMapping("/authenticate")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody JwtRequest authRequest) throws Exception {
        this.authenticate(authRequest.getUsername(), authRequest.getPassword());

        final UserDetails userDetails = userDetailsService.loadUserByUsername(authRequest.getUsername());
        final String token = tokenUtil.generateToken(userDetails);

        return ResponseEntity.ok(new JwtResponse(token));
    }

    // Registramos un nuevo usuario que recogemos del body de la peticion
    // lo guardamos en la bbdd y devolvemos el resultado
    @PostMapping("/register")
    public ResponseEntity<?> saveUser(@RequestBody UserDTO user) throws Exception {
        System.out.println("TEST[JwtAuthenticationController]: /register -> " + user.getUsername());
        return ResponseEntity.ok(userDetailsService.save(user));
    }

    // Mandaremos las credenciales de autenticacion al AuthenticationManager atraves
    // del metodo authenticate() pasandole por parametro un token generado al vuelo
    // con las credenciales del usuario.
    private void authenticate(String username, String password) throws Exception {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        }
        catch (DisabledException e) {
            throw new Exception("USER_DISABLED", e);
        }
        catch (BadCredentialsException e){
            throw new Exception("INVALID_CREDENTIALS", e);
        }
    }
}
