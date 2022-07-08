package io.getarrays.userservice;

import io.getarrays.userservice.domain.Role;
import io.getarrays.userservice.domain.User;
import io.getarrays.userservice.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class UserserviceApplication {

    public static void main(String[] args) {
        SpringApplication.run(UserserviceApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner runner(UserService userService) {
        return args -> {
            userService.saveRole(new Role("ROLE_USER"));
            userService.saveRole(new Role("ROLE_MANAGER"));
            userService.saveRole(new Role("ROLE_ADMIN"));
            userService.saveRole(new Role("ROLE_SUPER_ADMIN"));

            userService.saveUser(
                    new User(
                            "Saugat",
                            "raisaugat123",
                            "password",
                            new ArrayList<>()
                    )
            );
            userService.saveUser(
                    new User(
                            "Ram",
                            "rairaim123",
                            "password",
                            new ArrayList<>()
                    )
            );
            userService.saveUser(
                    new User(
                            "Rajani",
                            "raijani123",
                            "password",
                            new ArrayList<>()
                    )
            );
            userService.saveUser(
                    new User(
                            "Dipen",
                            "kafledipen123",
                            "password",
                            new ArrayList<>()
                    )
            );
            userService.saveUser(
                    new User(
                            "Binod",
                            "bomzznbinod123",
                            "password",
                            new ArrayList<>()
                    )
            );

            userService.addRoleToUser("raisaugat123", "ROLE_SUPER_ADMIN");
            userService.addRoleToUser("rairaim123", "ROLE_ADMIN");
            userService.addRoleToUser("raijani123", "ROLE_MANAGER");
            userService.addRoleToUser("kafledipen123", "ROLE_ADMIN");
            userService.addRoleToUser("bomzznbinod123", "ROLE_ADMIN");
            userService.addRoleToUser("bomzznbinod123", "ROLE_USER");
        };
    }

}
