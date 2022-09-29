package com.github.anoopgarlapati.samples.saml.resource;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class HomeResource {

    @RequestMapping("/")
    public String home(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model) {
        model.addAttribute("name", principal.getName());
        model.addAttribute("emailAddress", principal.getFirstAttribute("email").toString());
        Map<String, String> userAttributes = new HashMap<>();
        Map<String, List<Object>> attributes = principal.getAttributes();
        if (attributes != null) {
            attributes.keySet().forEach(attributeKey -> userAttributes.put(attributeKey, principal.getFirstAttribute(attributeKey)));
        }
        model.addAttribute("userAttributes", principal.getAttributes());
        return "home";
    }

}
