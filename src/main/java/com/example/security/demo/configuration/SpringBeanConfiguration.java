package com.example.security.demo.configuration;

import com.example.security.demo.filter.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

@Configuration
/*
EnableWebSecurity this annotation Enable Authentication
 */
@EnableWebSecurity
/*
EnableMethodSecurity annotation enables @PreAuthorize
Means it will activate Role based Authorization
 */
@EnableMethodSecurity
public class SpringBeanConfiguration {

    /*
    This Method is defined in org.springframework.boot.autoconfigure.security.servlet.SpringBootWebSecurityConfiguration
    Override this method to customize the Sign in functionality

     */

    private DataSource dataSource;

    private AuthEntryPointJwt authEntryPointJwt;

    public SpringBeanConfiguration(DataSource dataSource, AuthEntryPointJwt authEntryPointJwt){
        this.authEntryPointJwt = authEntryPointJwt;
        this.dataSource = dataSource;
    }

    @Bean
    public AuthTokenFilter authTokenFilter(){
        return new AuthTokenFilter();
    }


    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> (
                requests.requestMatchers("/h2-console/**").permitAll() // H2 DB Setup
                        .requestMatchers("/signin").permitAll()
                .anyRequest()).authenticated());

        /*
        Just for H2 DB setup
         */
        http.headers(headers->headers
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));

        /* Disabled form Login
        http.formLogin(Customizer.withDefaults());
        */
        /*
        Session Policy is Converted to Stateless so that cookies are not generated
         */
        http.sessionManagement(session->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.exceptionHandling(exception-> exception.authenticationEntryPoint(authEntryPointJwt));
        http.csrf(CsrfConfigurer::disable);

        //http.httpBasic(Customizer.withDefaults());
        http.addFilterBefore(authTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(){
        /*UserDetails user1 = User.withUsername("user1")
                .password(passwordEncoder().encode("password1"))
                .roles("USER")
                .build();
        UserDetails user2 = User.withUsername("user2")
                .password(passwordEncoder().encode("password2"))
                .roles("ADMIN")
                .build();*/
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        //jdbcUserDetailsManager.createUser(user1);
        //jdbcUserDetailsManager.createUser(user2);
        return jdbcUserDetailsManager;
        /*
        InMemoryUserDetailsManager for In memory
         */
        //return new InMemoryUserDetailsManager(user1, user2);
    }


    @Bean
    public CommandLineRunner initData(UserDetailsService userDetailsService){

        return args->{

            JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;
        UserDetails user1 = User.withUsername("user1")
                .password(passwordEncoder().encode("password1"))
                .roles("USER")
                .build();
        UserDetails user2 = User.withUsername("user2")
                .password(passwordEncoder().encode("password2"))
                .roles("ADMIN")
                .build();
            manager.createUser(user1);
            manager.createUser(user2);
        };
    }


    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }
}
