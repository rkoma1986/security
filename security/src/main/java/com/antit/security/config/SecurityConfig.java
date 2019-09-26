package com.antit.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.antit.security.security.CustomUserDetailsService;
import com.antit.security.security.JwtAuthenticationEntryPoint;
import com.antit.security.security.JwtAuthenticationFilter;

@Configuration
//This is the primary spring security annotation that is used to enable web security in a project.
@EnableWebSecurity 
// This is used to enable method level security based on annotations. You can use following three types of annotations for securing your methods 
@EnableGlobalMethodSecurity(
		/*
		 * securedEnabled: It enables the @Secured annotation using which you can protect your controller/service methods like so:
		 * @Secured("ROLE_ADMIN")
		 * public User getAllUsers() {}
		 */
        securedEnabled = true, 
        /*
         * jsr250Enabled: It enables the @RolesAllowed annotation that can be used like this:
         * @RolesAllowed("ROLE_ADMIN")
		 * public Poll createPoll() {}	
         */
        jsr250Enabled = true,
        /*
         * prePostEnabled: It enables more complex expression based access control syntax with @PreAuthorize and @PostAuthorize annotations:
         * @PreAuthorize("hasRole('USER')")
		 * public Poll createPoll() {}
         */
        prePostEnabled = true
)
/*
 * WebSecurityConfigurerAdapter implements Spring Security’s WebSecurityConfigurer interface. 
 * It provides default security configurations and allows other classes to extend it and customize 
 * the security configurations by overriding its methods.
 * Our SecurityConfig class extends WebSecurityConfigurerAdapter and overrides some of its methods to provide custom security configurations.
 */
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
    CustomUserDetailsService customUserDetailsService;

    @Autowired
    private JwtAuthenticationEntryPoint unauthorizedHandler;

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }

    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder
                .userDetailsService(customUserDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .cors()
                    .and()
                .csrf()
                    .disable()
                .exceptionHandling()
                    .authenticationEntryPoint(unauthorizedHandler)
                    .and()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                .authorizeRequests()
                    .antMatchers("/",
                        "/favicon.ico",
                        "/**/*.png",
                        "/**/*.gif",
                        "/**/*.svg",
                        "/**/*.jpg",
                        "/**/*.html",
                        "/**/*.css",
                        "/**/*.js")
                        .permitAll()
                    .antMatchers("/api/auth/**")
                        .permitAll()
                    .antMatchers("/api/user/checkUsernameAvailability", "/api/user/checkEmailAvailability")
                        .permitAll()
                    .antMatchers(HttpMethod.GET, "/api/polls/**", "/api/users/**")
                        .permitAll()
                    .anyRequest()
                        .authenticated();

        // Add our custom JWT security filter
        http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

    }
}
