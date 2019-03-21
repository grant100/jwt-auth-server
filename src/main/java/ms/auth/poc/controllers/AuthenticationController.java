package ms.auth.poc.controllers;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import ms.auth.poc.security.KeyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@RestController
public class AuthenticationController {
    private KeyService keyService;

    @Autowired
    public AuthenticationController(KeyService keyService) {
        this.keyService = keyService;
    }

    @RequestMapping(value = "/id-token", method = RequestMethod.GET)
    public String idToken() throws Exception {
        KeyPair keyPair = keyService.getKeyPair();
        String token = null;
        try {
            Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate());
            token = JWT.create()
                    .withIssuer("auth.service.poc")
                    .sign(algorithm);
        } catch (JWTCreationException exception) {
            //Invalid Signing configuration / Couldn't convert Claims.
        }
        return token;
    }
}
