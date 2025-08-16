package com.jay.authify.io;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ResetPasswordRequest {

    @NotBlank(message = "New Password is required!")
    private String newPassword;
    @NotBlank(message = "Otp is Required")
    private String otp;
    @NotBlank(message = "Email is Required")
    private String email;
}
