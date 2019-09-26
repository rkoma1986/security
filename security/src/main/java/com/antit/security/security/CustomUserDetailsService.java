package com.antit.security.security;



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.antit.security.model.User;
import com.antit.security.repository.UserRepository;
/*
 * To authenticate a User or perform various role-based checks, Spring security needs to load users details somehow.

For this purpose, It consists of an interface called UserDetailsService which has a single method that loads a user based on username-

UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;

We’ll define a CustomUserDetailsService that implements UserDetailsService interface and provides the implementation for loadUserByUsername() method.

Note that, the loadUserByUsername() method returns a UserDetails object that Spring Security uses for performing various authentication and role based validations.

In our implementation, We’ll also define a custom UserPrincipal class that will implement UserDetails interface, and return the UserPrincipal object from loadUserByUsername() method.
 */
@Service
public class CustomUserDetailsService implements UserDetailsService {

	@Autowired
    UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String usernameOrEmail)
            throws UsernameNotFoundException {
        // Let people login with either username or email
        User user = userRepository.findByUsernameOrEmail(usernameOrEmail, usernameOrEmail)
                .orElseThrow(() -> 
                        new UsernameNotFoundException("User not found with username or email : " + usernameOrEmail)
        );

        return UserPrincipal.create(user);
    }

    // This method is used by JWTAuthenticationFilter
    @Transactional
    public UserDetails loadUserById(Long id) {
        User user = userRepository.findById(id).orElseThrow(
            () -> new UsernameNotFoundException("User not found with id : " + id)
        );

        return UserPrincipal.create(user);
    }
}
