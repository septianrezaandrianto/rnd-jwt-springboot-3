package com.security.rndjwt.repositories;

import com.security.rndjwt.constants.EnumRole;
import com.security.rndjwt.entities.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByRole(EnumRole role);

}
