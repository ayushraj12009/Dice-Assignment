package com.dice.rapidapi.Controller;


import com.dice.rapidapi.Config.JwtProvider;
import com.dice.rapidapi.Exception.ClientException;
import com.dice.rapidapi.Model.Client;
import com.dice.rapidapi.Repository.ClientRepository;
import com.dice.rapidapi.Response.AuthResponse;
import com.dice.rapidapi.Service.ClientDetailServiceImplementation;
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
    private ClientDetailServiceImplementation clientDetailService;


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
        String email = client.getEmail();
        String password = client.getPassword();

        Client temp = clientRepository.findByEmail(email);

        if(temp == null){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Email is not available in database kindly signup with with this email ID " + email);
        }

        Authentication authentication = authenticate(email,password);
        String token = jwtProvider.generateToken(authentication);


        AuthResponse res = new AuthResponse();
        res.setJwt(token);
        res.setStatus(true);


        return new ResponseEntity<AuthResponse>(res,HttpStatus.ACCEPTED);
    }



    private Authentication authenticate(String username, String password) {
        UserDetails clientDetails = clientDetailService.loadUserByUsername(username);

        if(clientDetails == null) {
            throw new BadCredentialsException("Invalid name...");
        }

        if(!passwordEncoder.matches(password, clientDetails.getPassword())) {
            System.out.println("Password Wrong");
          throw new BadCredentialsException("Password Wrong");
        }

        return new UsernamePasswordAuthenticationToken(clientDetails,null,clientDetails.getAuthorities());

    }



    @GetMapping("/forecastSummaryByLocationName")
    public ResponseEntity<String> getForecast() {
        String apiUrl = "https://forecast9.p.rapidapi.com/rapidapi/forecast/Berlin/summary/";

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

        // to use this API,subscription is required, price $200 per month.
    @GetMapping("/HourlyForecastSummaryByLocationName")
    public ResponseEntity<String> getForecastByHourly() {
        String apiUrl = "https://forecast9.p.rapidapi.com/rapidapi/forecast/Berlin/hourly/?locationName=Berlin";

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
