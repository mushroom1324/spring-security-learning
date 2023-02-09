package com.example.security1.config.oauth;

import com.example.security1.config.auth.PrincipalDetails;
import com.example.security1.config.oauth.provider.FacebookUserInfo;
import com.example.security1.config.oauth.provider.GoogleUserInfo;
import com.example.security1.config.oauth.provider.NaverUserInfo;
import com.example.security1.config.oauth.provider.OAuth2UserInfo;
import com.example.security1.model.User;
import com.example.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private UserRepository userRepository;

    // After treatment function: userRequest data taken from Google
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("userRequest: " + userRequest.getClientRegistration()); // can tell which OAuth used (Google)
        System.out.println("userRequest: " + userRequest.getAccessToken().getTokenValue());

        OAuth2User oAuth2User = super.loadUser(userRequest);

        // use loadUser() to get userinfo
        System.out.println("getAttributes: " + oAuth2User.getAttributes());

        OAuth2UserInfo oAuth2UserInfo = null;

        if(userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            System.out.println("Google login request");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());

        } else if(userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
            System.out.println("Facebook login request");
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());

        } else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
            System.out.println("Naver login request");
            oAuth2UserInfo = new NaverUserInfo((Map)oAuth2User.getAttributes().get("response"));

        } else {
            System.out.println("service currently not provided.");
        }

        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId;
        String password = UUID.randomUUID().toString();
        String email = oAuth2UserInfo.getEmail();
        String role = "USER";

        User userEntity = userRepository.findByUsername(username);

        if(userEntity == null) {
            System.out.println("Registered with OAuth.");
            userEntity = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        } else {
            System.out.println("User already registered with OAuth.");
        }

        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());

    }
}
