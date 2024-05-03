package com.dice.rapidapi.Controller;


import com.dice.rapidapi.Config.JwtProvider;
import com.dice.rapidapi.Exception.ClientException;
import com.dice.rapidapi.Model.Client;
import com.dice.rapidapi.Repository.ClientRepository;
import com.dice.rapidapi.Response.AuthResponse;
import com.dice.rapidapi.Service.CustomUserDetailsServiceImplementation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;


@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private ClientRepository clientRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtProvider jwtProvider;

    @Autowired
    private CustomUserDetailsServiceImplementation customeUserDetails;


    @PostMapping("/signup")
    public ResponseEntity<?> createUserHandler(@RequestBody Client client) throws ClientException {

        String email=client.getEmail();
        String password = client.getPassword();
        String fullName = client.getFullName();


        Client isEmailExist = clientRepository.findByEmail(email);
        if(isEmailExist != null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Email is already used with another account");
        }
        Client createdClinet = new Client();
        createdClinet.setEmail(email);
        createdClinet.setFullName(fullName);
        createdClinet.setPassword(passwordEncoder.encode(password));

        Client savedClient = clientRepository.save(createdClinet);

        Authentication authentication = new UsernamePasswordAuthenticationToken(email, password);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String token = jwtProvider.generateToken(authentication);

        AuthResponse res = new AuthResponse();
        res.setJwt(token);
        res.setStatus(true);

        return new ResponseEntity<AuthResponse>(res,HttpStatus.CREATED);
    }


    @PostMapping("/signin")
    public ResponseEntity<?> signin(@RequestBody Client client){
        String name = client.getEmail();
        String password = client.getPassword();

//        Client isEmailExist = clientRepository.findByEmail(name);
//        if(isEmailExist != null) {
//            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
//                    .body("Email is not valid");
//        }

        Authentication authentication = authenticate(name,password);
        String token = jwtProvider.generateToken(authentication);

        AuthResponse res = new AuthResponse();
        res.setJwt(token);
        res.setStatus(true);

        return new ResponseEntity<AuthResponse>(res,HttpStatus.ACCEPTED);
    }


    private Authentication authenticate(String username, String password) {
        UserDetails userDetails = customeUserDetails.loadUserByUsername(username);

        if(userDetails == null) {
            throw new BadCredentialsException("Invalid name...");
        }
        if(!passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new BadCredentialsException("Invalid username or password");
        }
        return new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());

    }


    @GetMapping("/forecast")
    public ResponseEntity<String> getForecast() {
        String apiUrl = "https://forecast9.p.rapidapi.com/rapidapi/forecast/Berlin/summary/?locationName=Berlin";

        HttpHeaders headers = new HttpHeaders();
        headers.set("X-RapidAPI-Key", "6efddc62camshdc3f3ebd39b9c81p1e435ajsn9628e62f06ba");
        headers.set("X-RapidAPI-Host", "forecast9.p.rapidapi.com");

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.exchange(
                apiUrl,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                String.class
        );

        return response;
    }



}
