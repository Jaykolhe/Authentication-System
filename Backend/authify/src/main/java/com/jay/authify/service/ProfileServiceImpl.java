package com.jay.authify.service;

import com.jay.authify.entity.UserEntity;
import com.jay.authify.io.ProfileRequest;
import com.jay.authify.io.ProfileResponse;
import com.jay.authify.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

@Service
@RequiredArgsConstructor
public class ProfileServiceImpl implements ProfileService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    @Override
    public ProfileResponse createProfile(ProfileRequest request) {
        UserEntity userEntity = convertToUserEntity(request);
        if(!userRepository.existsByEmail(userEntity.getEmail())){
            userEntity = userRepository.save(userEntity);
            return convertToProfileResponse(userEntity);
        }
        throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");

    }

    @Override
    public ProfileResponse getProfile(String email) {
       UserEntity existingUser = userRepository.findByEmail(email)
                .orElseThrow(()-> new UsernameNotFoundException("User not found: "+email));

       return convertToProfileResponse(existingUser);

    }

    @Override
    public void sendResetOtp(String email) {
        UserEntity existingUser = userRepository.findByEmail(email)
                                                .orElseThrow(()-> new UsernameNotFoundException("User not found: "+email));

        //Generate 6 digit Otp
        String otp = String.valueOf(ThreadLocalRandom.current().nextInt(100000, 1000000));
        //calculate expiry time(current time + 15 minutes in miliseconds)
        long expiryTime = System.currentTimeMillis() +(15*60*1000);

        //update the profile entity
        existingUser.setResetOtp(otp);
        existingUser.setResetOtpExpireAt(expiryTime);

        //save into the database
        userRepository.save(existingUser);

        try{
            //send the reset otp email
            emailService.sendResetOtpEmail(existingUser.getEmail(), otp);

        }catch(Exception e){
            throw  new RuntimeException("Unable to send Email");
        }

    }

    @Override
    public void resetPassword(String email, String otp, String newPassword) {
        UserEntity existingUser = userRepository.findByEmail(email)
                .orElseThrow(()-> new UsernameNotFoundException("User not found: "+email));
        if(existingUser.getResetOtp() == null || !existingUser.getResetOtp().equals(otp)){
            throw new RuntimeException("Invalid OTP");
        }
        if(existingUser.getResetOtpExpireAt() < System.currentTimeMillis()){
            throw new RuntimeException("OTP Expired");
        }

        existingUser.setPassword(passwordEncoder.encode(newPassword));
        existingUser.setResetOtp(null);
        existingUser.setResetOtpExpireAt(0L);

        userRepository.save(existingUser);

    }

    @Override
    public void sendOtp(String email) {
        UserEntity existingUser = userRepository.findByEmail(email)
                .orElseThrow(()-> new UsernameNotFoundException("User not found: "+email));
        if(existingUser.getIsAccountVerified() != null && existingUser.getIsAccountVerified()){
            return;
        }

        //Generate 6 digit otp
        String otp = String.valueOf(ThreadLocalRandom.current().nextInt(100000, 1000000));
        //Expiry time 24 hours
        long expiryTime = System.currentTimeMillis() +(24*60*60*1000);

        //Update the user Entity
        existingUser.setVerifyOtp(otp);
        existingUser.setVerifyOtpExpireAt(expiryTime);

        //Save to database
        userRepository.save(existingUser);

        try{
            emailService.sendOtpEmail(existingUser.getEmail(), otp);

        }catch(Exception e){
            throw  new RuntimeException("Unable to send Email");
        }


    }

    @Override
    public void verifyOtp(String email, String otp) {

       UserEntity existingUser = userRepository.findByEmail(email)
                .orElseThrow(()-> new UsernameNotFoundException("User not found: "+email));

       if(existingUser.getVerifyOtp() == null || !existingUser.getVerifyOtp().equals(otp)){
           throw new RuntimeException("Invalid OTP");
       }
       if(existingUser.getVerifyOtpExpireAt() < System.currentTimeMillis()){
           throw new RuntimeException("OTP Expired");
       }

       existingUser.setIsAccountVerified(true);
       existingUser.setVerifyOtp(null);
       existingUser.setVerifyOtpExpireAt(0L);
       userRepository.save(existingUser);

    }


    private ProfileResponse convertToProfileResponse(UserEntity userEntity) {
           return ProfileResponse.builder()
                    .name(userEntity.getName())
                    .email(userEntity.getEmail())
                    .userId(userEntity.getUserId())
                    .isAccountVerified(userEntity.getIsAccountVerified())
                    .build();

    }

    private UserEntity convertToUserEntity(ProfileRequest request) {
           return UserEntity.builder()
                    .email(request.getEmail())
                    .userId(UUID.randomUUID().toString())
                    .name(request.getName())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .isAccountVerified(false)
                    .resetOtpExpireAt(0L)
                    .verifyOtp(null)
                    .verifyOtpExpireAt(0L)
                    .resetOtp(null)
                    .build();
    }
}
