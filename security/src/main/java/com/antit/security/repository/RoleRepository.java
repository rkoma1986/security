package com.antit.security.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.antit.security.model.Role;
import com.antit.security.model.RoleName;

public interface RoleRepository extends JpaRepository<Role, Long> {

	Optional<Role> findByName(RoleName roleName);
}
