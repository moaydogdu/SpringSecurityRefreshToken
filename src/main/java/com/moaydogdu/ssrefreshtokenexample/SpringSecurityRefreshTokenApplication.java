package com.moaydogdu.ssrefreshtokenexample;

import com.moaydogdu.ssrefreshtokenexample.security.auth.AuthenticationService;
import com.moaydogdu.ssrefreshtokenexample.security.auth.RegisterRequest;
import com.moaydogdu.ssrefreshtokenexample.security.user.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SpringSecurityRefreshTokenApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityRefreshTokenApplication.class, args);
    }

    public CommandLineRunner commandLineRunner(
            AuthenticationService service
    ){
        return args -> {
            //Auto Admin Save for test.
            var admin = RegisterRequest.builder()
                    .firstname("Muhammet Oguzhan")
                    .lastname("AYDOĞDU")
                    .email("m.o.aydogdu@outlook.com")
                    .password("şifre1234")
                    .role(Role.ADMIN)
                    .build();
            System.out.println("Admin token: "+service.register(admin).getAccessToken());

            //Auto Manager Save for rest.
            var manager = RegisterRequest.builder()
                    .firstname("Nurettin")
                    .lastname("BAŞTÜRK")
                    .email("nurettinbasturk@gmail.com")
                    .password("şifre1234")
                    .role(Role.MANAGER)
                    .build();

            System.out.println("Manager token: "+ service.register(manager).getAccessToken());
        };
    }

}
