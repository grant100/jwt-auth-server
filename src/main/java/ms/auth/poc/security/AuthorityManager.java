package ms.auth.poc.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@ConfigurationProperties(prefix = "authorities")
public class AuthorityManager {

    private List<Application> applications;

    List<Application> getApplications() {
        return applications;
    }

    public void setApplications(List<Application> applications) {
        // prevent modification
        if (this.applications == null) {
            this.applications = Collections.unmodifiableList(new ArrayList<>(applications));
        }
    }

    static class Application {
        String name;
        List<String> authorities;


        public String getName() {
            return name;
        }


        public void setName(String name) {
            // prevent modification
            if (this.name == null) {
                this.name = name;
            }
        }

        public List<String> getAuthorities() {
            return authorities;
        }

        public void setAuthorities(List<String> entitlements) {
            // prevent modification
            if (this.authorities == null) {
                this.authorities = Collections.unmodifiableList(new ArrayList<>(entitlements));
            }
        }
    }

    List<String> getEntitlementsByIssuer(String issuer) throws Exception {
        for (Application app : this.applications) {
            if (app.getName().equals(issuer)) {
                return app.getAuthorities();
            }
        }
        throw new Exception("No entitlements found for issuer");
    }
}