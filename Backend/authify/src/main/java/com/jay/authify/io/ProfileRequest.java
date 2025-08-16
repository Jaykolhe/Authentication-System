package com.jay.authify.io;

import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ProfileRequest {

    @NotBlank(message = "Name Should be not Empty")
    private String name;
    @Email(message = "Enter Valid Email Address")
    @NotNull(message = "Email Should not be Empty")
    private String email;
    @Size(min = 6,message = "Password must be atleast 6 characters")
    private String password;

}
