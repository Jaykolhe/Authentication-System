package com.jay.authify.controller;

import com.jay.authify.entity.UserEntity;
import com.jay.authify.io.ProfileRequest;
import com.jay.authify.io.ProfileResponse;
import com.jay.authify.service.EmailService;
import com.jay.authify.service.ProfileService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class ProfileController {

    private final ProfileService profileService;
    private final EmailService emailService;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public ProfileResponse register(@Valid @RequestBody ProfileRequest request) {
            ProfileResponse response= profileService.createProfile(request);
            // send Welcome email
            emailService.sendWelcomeEmail(response.getEmail(), response.getName());
            return response;
    }

    @GetMapping("/profile")
    public ProfileResponse getProfile(@CurrentSecurityContext(expression = "authentication?.name")String email) {
        return profileService.getProfile(email);
    }



}
