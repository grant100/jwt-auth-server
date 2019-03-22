package ms.auth.poc.security.rules.cc;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import ms.auth.poc.security.ClaimConstants;
import ms.auth.poc.security.exceptions.RuleViolationException;
import ms.auth.poc.security.rules.Rule;
import org.apache.commons.codec.binary.Base64;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

public class CCHeaderRule implements Rule {
    private final String NONE = "none";
    private DecodedJWT clientCredential;
    private List<String> encryptionTypes;

    public CCHeaderRule(DecodedJWT clientCredential, List<String> encryptionTypes) {
        this.encryptionTypes = encryptionTypes;
        this.clientCredential = clientCredential;
    }

    @Override
    public void execute() throws RuleViolationException {
        String typ = clientCredential.getType();
        String alg = clientCredential.getAlgorithm();

        if (typ == null || typ.isEmpty()) {
            throw new RuleViolationException("Missing Client Credential typ header");
        }

        if (alg == null || alg.isEmpty()) {
            throw new RuleViolationException("Missing Client Credential alg header");
        }

        if (alg.equals(NONE)) {
            throw new RuleViolationException("Invalid Client Credential alg header value");
        }

        if (!encryptionTypes.contains(alg)) {
            throw new RuleViolationException("Invalid Client Credential alg header value");
        }
    }

    public Algorithm getAlgorithm(String key){
        if(clientCredential.getAlgorithm().equals(ClaimConstants.HMAC_256)){
            return Algorithm.HMAC256(key);
        }

        try{
            if(clientCredential.getAlgorithm().equals(ClaimConstants.RSA_256)){
                key = key.replace("-----BEGIN CERTIFICATE-----","");
                key = key.replace("-----END CERTIFICATE-----","");
                byte[] encodedCert = key.getBytes("UTF-8");
                byte[] decodedCert = Base64.decodeBase64(encodedCert);

                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                InputStream in = new ByteArrayInputStream(decodedCert);
                X509Certificate certificate = (X509Certificate)certFactory.generateCertificate(in);

                PublicKey publicKey = certificate.getPublicKey();
                return Algorithm.RSA256((RSAPublicKey)publicKey, null);
            }
        }catch (Exception e){
            throw new RuleViolationException("Could not instantiate RSA public key", e);
        }
        return null;
    }
}
