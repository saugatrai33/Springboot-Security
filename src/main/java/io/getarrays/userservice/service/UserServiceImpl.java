package io.getarrays.userservice.service;

import io.getarrays.userservice.Constant;
import io.getarrays.userservice.domain.Role;
import io.getarrays.userservice.domain.User;
import io.getarrays.userservice.repo.RoleRepo;
import io.getarrays.userservice.repo.UserRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {
    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var user = userRepo.findByUsername(username)
                .orElseThrow(
                        () -> {
                            log.info("User with name username {} not found.", username);
                            throw new UsernameNotFoundException(
                                    "User with name username not found."
                            );
                        }
                );

        log.info("User found with username {}", username);
        Collection<SimpleGrantedAuthority> authorities =
                new ArrayList<>();

        user.getRoles()
                .forEach(role -> authorities.add(
                        new SimpleGrantedAuthority(role.getName())
                ));

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                authorities
        );
    }

    @Override
    public User saveUser(User user) {
        log.info(
                String.format(
                        Constant.MSG_SAVE_USER,
                        user.getUsername()
                )
        );
        user.setPassword(
                passwordEncoder.encode(
                        user.getPassword()
                )
        );
        return userRepo.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info(
                String.format(
                        Constant.MSG_SAVE_ROLE,
                        role.getName()
                )
        );
        return roleRepo.save(role);
    }

    @Override
    public void addRoleToUser(String userName, String roleName) {
        log.info(
                "adding role {} to user with username {}",
                roleName,
                userName
        );
        userRepo.findByUsername(userName)
                .ifPresentOrElse(user -> roleRepo.findByName(roleName)
                                .ifPresentOrElse(role -> user.getRoles().add(role),
                                        () -> log.error(
                                                String.format(
                                                        Constant.MSG_ROLE_NOT_FOUND,
                                                        roleName
                                                )
                                        )
                                ),
                        () -> log.error(
                                String.format(
                                        Constant.MSG_USER_NOT_FOUND,
                                        userName
                                )
                        )
                );
    }

    @Override
    public User getUser(String userName) throws RuntimeException {
        log.info(
                "fetching user with username {} ----------->",
                userName
        );
        return userRepo.findByUsername(userName)
                .orElseThrow(() -> new RuntimeException(
                                String.format(
                                        Constant.MSG_USER_NOT_FOUND,
                                        userName
                                )
                        )
                );
    }

    @Override
    public List<User> getUsers() {
        log.info("fetching all users--------------->");
        return userRepo.findAll();
    }
}
