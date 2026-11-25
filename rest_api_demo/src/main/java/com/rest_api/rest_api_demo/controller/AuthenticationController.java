package com.rest_api.rest_api_demo.controller;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.rest_api.rest_api_demo.dto.AuthLoginDto;
import com.rest_api.rest_api_demo.dto.AuthRoleRegisterDto;
import com.rest_api.rest_api_demo.dto.AuthUserRegisterDto;
import com.rest_api.rest_api_demo.entity.Auth_Role;
import com.rest_api.rest_api_demo.entity.Auth_User;
import com.rest_api.rest_api_demo.repository.AuthRoleRepository;
import com.rest_api.rest_api_demo.repository.AuthUserRepository;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;


@RestController 
@RequestMapping("/api/auth")
public class AuthenticationController {

  private AuthenticationManager authenticationManager;
  public AuthenticationManager getAuthenticationManager() {
    return authenticationManager;
  }

  public void setAuthenticationManager(AuthenticationManager authenticationManager) {
    this.authenticationManager = authenticationManager;
  }

  private AuthUserRepository authUserRepo;
  private AuthRoleRepository authRoleRepo;    private BCryptPasswordEncoder passwordEncoder;

  public AuthenticationController(AuthenticationManager authenticationManager,
                                    AuthUserRepository authUserRepo,
                                    AuthRoleRepository authRoleRepo,
                                    BCryptPasswordEncoder passwordEncoder) {
    this.authenticationManager = authenticationManager;
    this.authUserRepo = authUserRepo;
    this.authRoleRepo = authRoleRepo;
    this.passwordEncoder = passwordEncoder;
    }

  @PostMapping("/register_authorized_role")
  public ResponseEntity<String> register_authRole(
          @RequestBody AuthRoleRegisterDto authRoleRegisterDto) {
      if (authRoleRepo.existsByName(authRoleRegisterDto.getName())){
        return new ResponseEntity<>(authRoleRegisterDto.getName() + " already created.",
            HttpStatus.BAD_REQUEST);
      }

  Auth_Role auth_role = new Auth_Role();
  auth_role.setName(authRoleRegisterDto.getName());
  authRoleRepo.save(auth_role);

  return new ResponseEntity<>(auth_role.getName()+ " is successfully created.",
            HttpStatus.OK);
  }

  @PostMapping("/register_authorized_user")
  public ResponseEntity<String> register_authUser(@RequestBody AuthUserRegisterDto authUserRegisterDto) {
    if (authUserRepo.existsByUsername(authUserRegisterDto.getUsername())){ 
      return new ResponseEntity<>(authUserRegisterDto.getUsername()+ " taken na siya. awts :(",
                HttpStatus.BAD_REQUEST);
    }

  Auth_User auth_user = new Auth_User();
  auth_user.setUsername(authUserRegisterDto.getUsername());
  auth_user.setPassword(passwordEncoder.encode(authUserRegisterDto.getPassword()));

  Auth_Role auth_role = authRoleRepo.findByName("USER")
                .orElseThrow(() -> new RuntimeException("Roles USER not found"));
  auth_user.setRoles(Collections.singletonList(auth_role));

  authUserRepo.save(auth_user);

  return new ResponseEntity<>(auth_user.getUsername() + " is successfully registered",
                HttpStatus.OK);
  }

  @PostMapping("/auth_login")
    public ResponseEntity<String> login(@RequestBody AuthLoginDto authLoginDto) {
        Authentication authenticate = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authLoginDto.getUsername(),
                        authLoginDto.getPassword()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authenticate);

        return new ResponseEntity<>("Sign in successfully!", HttpStatus.OK);
    }

  @PostMapping("/auth_login_session")
    public ResponseEntity<?> loginWithSession(@RequestBody AuthLoginDto authLoginDto,
                                          HttpServletRequest request) {
    Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                    authLoginDto.getUsername(),
                    authLoginDto.getPassword()
            )
    );

    SecurityContextHolder.getContext().setAuthentication(authentication);
    HttpSession session = request.getSession(true);
    session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());

    Map<String, String> response = new HashMap<>();
    response.put("message", "Authenticated successfully via session cookie.");
    return ResponseEntity.ok(response);
  }


  @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request) {
      HttpSession session = request.getSession(false);
      if (session != null) {
        session.invalidate();
      }
    SecurityContextHolder.clearContext();
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body("Logged out from session container.");
  }


}


