package com.example.security.demo.controller;

import com.example.security.demo.configuration.AuthEntryPointJwt;
import com.example.security.demo.configuration.Jwtutils;
import com.example.security.demo.filter.AuthTokenFilter;
import com.example.security.demo.model.LoginRequest;
import com.example.security.demo.model.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class HelloWorldController {

    AuthenticationManager authenticationManager;

    Jwtutils jwtutils;

    public HelloWorldController(AuthenticationManager authenticationManager, Jwtutils jwtutils){
        this.authenticationManager = authenticationManager;
        this.jwtutils = jwtutils;
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/hello")
    public String hello(){
        return "Hello User";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String helloAdmin(){
        return "Hello Admin";
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest request){
        Authentication authentication;
        try{

            authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(
                            request.username(), request.password()));
        } catch(Exception ex){
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Bad Credentials");
            map.put("status", false);
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String jwtToken = jwtutils.generateTokenFromUsername(userDetails);
        List<String> roles = userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority).toList();

        LoginResponse response = new LoginResponse(jwtToken, userDetails.getUsername(), roles);
        return ResponseEntity.ok(response);
    }
}
