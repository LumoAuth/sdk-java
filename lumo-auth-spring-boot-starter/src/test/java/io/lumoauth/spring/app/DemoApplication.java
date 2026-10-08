package io.lumoauth.spring.app;

import io.lumoauth.spring.RequirePermission;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/** A minimal app for the end-to-end starter test: one public page, one protected API, one guarded service. */
@SpringBootApplication
public class DemoApplication {

    @RestController
    static class Api {
        private final Documents documents;

        Api(Documents documents) {
            this.documents = documents;
        }

        @GetMapping("/")
        String home() {
            return "home";
        }

        @GetMapping("/api/me")
        String me(@AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal) {
            return "hello " + principal.getName();
        }

        @GetMapping("/api/documents/{id}/edit")
        String edit(@PathVariable String id) {
            return documents.edit(id);
        }
    }

    @Service
    static class Documents {
        @RequirePermission("document.edit")
        public String edit(String id) {
            return "edited " + id;
        }
    }
}
