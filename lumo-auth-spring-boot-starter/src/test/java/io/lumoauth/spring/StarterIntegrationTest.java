package io.lumoauth.spring;

import io.lumoauth.spring.app.DemoApplication;
import io.lumoauth.spring.support.FakeServer;
import io.lumoauth.spring.support.FakeServer.Reply;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The starter end to end: properties alone produce an app where unauthenticated
 * browser requests are sent to the LumoAuth login, bearer tokens are resolved
 * through userinfo, and {@link RequirePermission} enforces RBAC server-side.
 */
@SpringBootTest(classes = DemoApplication.class, properties = {
    "lumoauth.org-id=acme",
    "lumoauth.api-key=test-key",
    "lumoauth.login.client-id=web-client",
    "lumoauth.login.client-secret=web-secret",
})
@AutoConfigureMockMvc
class StarterIntegrationTest {

    static final FakeServer SERVER = new FakeServer();

    @DynamicPropertySource
    static void lumoUrl(DynamicPropertyRegistry registry) {
        registry.add("lumoauth.url", SERVER::url);
    }

    @AfterAll
    static void stop() {
        SERVER.close();
    }

    @Autowired
    MockMvc mvc;

    @Test
    void publicPagesArePermitted() throws Exception {
        mvc.perform(get("/")).andExpect(status().isOk()).andExpect(content().string("home"));
    }

    @Test
    void browsersAreSentToLumoAuthLogin() throws Exception {
        mvc.perform(get("/api/me").accept("text/html"))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrlPattern("**/oauth2/authorization/lumoauth"));
    }

    @Test
    void bearerTokensAreResolvedThroughUserinfo() throws Exception {
        SERVER.on("/orgs/acme/api/v1/oauth/userinfo", req -> "Bearer GOOD".equals(req.header("Authorization"))
            ? Reply.json(Map.of("sub", "ada", "roles", List.of("editor")))
            : Reply.json(401, Map.of("error", "invalid_token")));
        mvc.perform(get("/api/me").header("Authorization", "Bearer GOOD"))
            .andExpect(status().isOk()).andExpect(content().string("hello ada"));
        mvc.perform(get("/api/me").header("Authorization", "Bearer BAD")).andExpect(status().isUnauthorized());
    }

    @Test
    void requirePermissionIsEnforced() throws Exception {
        SERVER.on("/orgs/acme/api/v1/oauth/userinfo", Reply.json(Map.of("sub", "ada")));
        SERVER.on("/api/v1/authz/check", req -> Reply.json(Map.of("allowed", "Bearer EDITOR".equals(req.header("Authorization")))));
        mvc.perform(get("/api/documents/1/edit").header("Authorization", "Bearer EDITOR"))
            .andExpect(status().isOk()).andExpect(content().string("edited 1"));
        mvc.perform(get("/api/documents/1/edit").header("Authorization", "Bearer VIEWER")).andExpect(status().isForbidden());
    }
}
