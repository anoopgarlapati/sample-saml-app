# Sample SAML Application

This is a Sample SAML Application using Spring Security SAML 2.0 Service Provider framework.

This sample uses WS1 Access as SAML 2.0 Identity Provider.

### Configure SAML Application in WS1 Access
Import Sample_SAML_App.zip resource config from `src/main/resources` directory in this repository into WS1 Access Web Apps Catalog. Then assign users to this application.

### Configure WS1 Access IdP metadata in this SAML Application
Modify `spring.security.saml2.relyingparty.registration.ws1access.assertingparty.metadata` property in application.properties to point to IdP metadata URL of WS1 Access tenant.

### Running the SAML SP server
```shell
./mvnw spring-boot:run
```
### Authenticate user using SP-init flow
Open http://localhost:8080/login in browser to initiate SP-init flow. Upon successful authentication, browser should redirect to http://localhost:8080/ where the user's details are displayed.

### Authenticate user using IdP-init flow
Log in as the user to the WS1 Access tenant and open this Sample SAML App from the Application Catalog. Upon successful authentication, browser should redirect to http://localhost:8080/ where the user's details are displayed.