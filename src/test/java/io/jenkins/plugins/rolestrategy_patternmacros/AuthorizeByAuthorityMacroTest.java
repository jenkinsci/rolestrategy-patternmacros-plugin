
package io.jenkins.plugins.rolestrategy_patternmacros;

import com.michelin.cio.hudson.plugins.rolestrategy.PermissionEntry;
import com.michelin.cio.hudson.plugins.rolestrategy.RoleBasedAuthorizationStrategy;
import com.synopsys.arc.jenkins.plugins.rolestrategy.Macro;
import com.synopsys.arc.jenkins.plugins.rolestrategy.RoleType;

import hudson.model.FreeStyleProject;
import hudson.model.Item;
import hudson.model.Job;
import hudson.security.Permission;

import org.jenkinsci.plugins.rolestrategy.Settings;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import java.io.IOException;
import java.util.List;

/**
 * Tests for {@link AbstractOwnershipRoleMacro} focusing on null and empty SID validation.
 */
@WithJenkins
public class AuthorizeByAuthorityMacroTest {

    private JenkinsRule j;

    @BeforeEach
    void setUp(JenkinsRule jenkinsRule) throws IOException {
        this.j = jenkinsRule;
        Settings.TREAT_USER_AUTHORITIES_AS_ROLES = true;
        RoleBasedAuthorizationStrategy strategy = new RoleBasedAuthorizationStrategy();
        Authentication adminUser = new UsernamePasswordAuthenticationToken("adminuser", "password");    
    
        strategy.doAddRole("globalRoles", "admin", "Overall/Administer", "true", "", "");
        strategy.doAssignUserRole("globalRoles", "admin", "adminUser");

        j.jenkins.setAuthorizationStrategy(strategy);

        SecurityContextHolder.getContext().setAuthentication(adminUser);
    }

    @AfterEach
    void tearDown() {
        Settings.TREAT_USER_AUTHORITIES_AS_ROLES = false;          
    }

    /**
     * Test that hasPermission returns false when PermissionEntry is null.
     */
    @Test
    public void testHasPermissionWithNullEntry() throws Exception {
        AuthorizeByAuthorityMacro macro = new AuthorizeByAuthorityMacro();
        FreeStyleProject project = j.createFreeStyleProject("pipeline-test");

        Permission permission = Item.READ;
        RoleType type = RoleType.Project;
        Macro macroParam = null; // Macro is not used in the null check logic

        boolean result = macro.hasPermission((PermissionEntry) null, permission, type, project, macroParam);

        assertThat("Access should be denied when PermissionEntry is null", result, equalTo(false));
    }

    /**
     * Test that hasPermission return true when Authority for the user matches on a viewer level, matching TEMPLATE_PATTERN pattern
     */
    @Test
    public void testCanAccessTemplatePattern() throws Exception {
        AuthorizeByAuthorityMacro macro = new AuthorizeByAuthorityMacro();
        FreeStyleProject project = j.createFreeStyleProject("pipeline-test");

        Permission permission = Item.READ;
        RoleType type = RoleType.Project;
        
        // Set currently logged user
        
        List<GrantedAuthority> authorities = List.of(
            new SimpleGrantedAuthority("viewer_test")
        );

        Authentication auth =
            new UsernamePasswordAuthenticationToken(
                "testuser",
                "password",
                authorities);

        SecurityContextHolder.getContext().setAuthentication(auth);

        String[] params = { "viewer", "TEMPLATE_PATTERN" };

        Macro macroParam = new Macro("AuthorizeByAuthority", 0, params);

        boolean result = macro.hasPermission("nullsid", permission, type, project, macroParam);

        assertThat("Access allowed with ", result, equalTo(true));
    }


    /**
     * Test that hasPermission return true when Authority for the user matches on a viewer level, matching PATTERN_TEMPLATE pattern
     */
    @Test
    public void testCanAccessPatternTemplate() throws Exception {
        AuthorizeByAuthorityMacro macro = new AuthorizeByAuthorityMacro();
        FreeStyleProject project = j.createFreeStyleProject("pipeline-test");

        Permission permission = Item.READ;
        RoleType type = RoleType.Project;
        
        List<GrantedAuthority> authorities = List.of(
            new SimpleGrantedAuthority("test_viewer")
        );

        Authentication auth =
            new UsernamePasswordAuthenticationToken(
                "testuser",
                "password",
                authorities);

        SecurityContextHolder.getContext().setAuthentication(auth);

        String[] params = { "viewer", "PATTERN_TEMPLATE" };

        Macro macroParam = new Macro("AuthorizeByAuthority", 0, params);

        boolean result = macro.hasPermission("nullsid", permission, type, project, macroParam);

        assertThat("Access allowed with ", result, equalTo(true));
    }

    /**
     * Test that hasPermission return true when Authority for the user matches on a viewer level, matching TEMPLATE_PATTERN pattern
     */
    @Test
    public void testMultiplePatterns() throws Exception {
        AuthorizeByAuthorityMacro macro = new AuthorizeByAuthorityMacro();
        FreeStyleProject project = j.createFreeStyleProject("pipeline-test");

        Permission permission = Item.READ;
        RoleType type = RoleType.Project;
        
        List<GrantedAuthority> authorities = List.of(
            new SimpleGrantedAuthority("test_viewer"),
            new SimpleGrantedAuthority("test_builder"),
            new SimpleGrantedAuthority("test_developer"),
            new SimpleGrantedAuthority("test_manager"),
            new SimpleGrantedAuthority("test_owner")
        );

        Authentication auth =
            new UsernamePasswordAuthenticationToken(
                "testuser",
                "password",
                authorities);

        SecurityContextHolder.getContext().setAuthentication(auth);

        Macro macroParam1 = new Macro("AuthorizeByAuthority", 0,  new String[]{ "viewer", "PATTERN_TEMPLATE" });
        Macro macroParam2 = new Macro("AuthorizeByAuthority", 1, new String[]{ "builder", "PATTERN_TEMPLATE" });

        boolean result1 = macro.hasPermission("nullsid", permission, type, project, macroParam1);
        assertThat("Access allowed with ", result1, equalTo(true));

        boolean result2 = macro.hasPermission("nullsid", permission, type, project, macroParam2);
        assertThat("Access allowed with ", result2, equalTo(true));

    }
    /**
     * Test that hasPermission return false when the user has the wrong authorities
     */
    @Test
    public void testWrongAuthoritiesBlock() throws Exception {
        AuthorizeByAuthorityMacro macro = new AuthorizeByAuthorityMacro();
        FreeStyleProject project = j.createFreeStyleProject("pipeline-test");

        Permission permission = Item.READ;
        RoleType type = RoleType.Project;
        List<GrantedAuthority> authorities = List.of(
            new SimpleGrantedAuthority("personal_viewer")
        );

        Authentication auth =
            new UsernamePasswordAuthenticationToken(
                "testuser",
                "password",
                authorities);

        SecurityContextHolder.getContext().setAuthentication(auth);

        String[] params = { "test", "TEMPLATE_PATTERN" };

        Macro macroParam = new Macro("AuthorizeByAuthority", 0, params);

        boolean result = macro.hasPermission("nullsid", permission, type, project, macroParam);

        assertThat("Access blocked with ", result, equalTo(false));
    }

    /**
     * Test that correct permissions are assigned to user with appropriate authority
    */
   
    @Test
    public void testPermissionTemplate() throws Exception {
        
        FreeStyleProject project = j.createFreeStyleProject("pipeline-test");

        RoleBasedAuthorizationStrategy strategy =  (RoleBasedAuthorizationStrategy)j.jenkins.getAuthorizationStrategy();
        strategy.doAddTemplate("builder",  "hudson.model.Item.Read,hudson.model.Item.Build", true);
        
        List<GrantedAuthority> authorities = List.of(
            new SimpleGrantedAuthority("test_builder")
        );

        JenkinsRule.DummySecurityRealm securityRealm = j.createDummySecurityRealm();
        j.jenkins.setSecurityRealm(securityRealm);
        j.jenkins.setAuthorizationStrategy(strategy);
        j.jenkins.setCrumbIssuer(null);
        
        Authentication auth =
            new UsernamePasswordAuthenticationToken(
                "testuser",
                "password",
                authorities);

        strategy.doAddRole("projectRoles", "@AuthorizeByAuthority(builder, PATTERN_TEMPLATE)",
            "",
            "true", "^pipeline.*", "builder");

        strategy.doAssignUserRole("projectRoles", "@AuthorizeByAuthority(builder, PATTERN_TEMPLATE)", "testuser");
        SecurityContextHolder.getContext().setAuthentication(auth);

        assertThat("Has build access to project from template ", project.hasPermission2(auth, Job.BUILD), equalTo(true));
    }


    /**
     * Test that user with wrong authority does not have template assigned using macro
    */
   
    @Test
    public void testPermissionTemplateNoAuthorityMatch() throws Exception {
        
        FreeStyleProject project = j.createFreeStyleProject("pipeline-test");

        RoleBasedAuthorizationStrategy strategy =  (RoleBasedAuthorizationStrategy)j.jenkins.getAuthorizationStrategy();
        strategy.doAddTemplate("builder",  "hudson.model.Item.Read,hudson.model.Item.Build", true);
        
        List<GrantedAuthority> authorities = List.of(
            new SimpleGrantedAuthority("test_viewer")
        );

        JenkinsRule.DummySecurityRealm securityRealm = j.createDummySecurityRealm();
        j.jenkins.setSecurityRealm(securityRealm);
        j.jenkins.setAuthorizationStrategy(strategy);
        j.jenkins.setCrumbIssuer(null);
        
        Authentication auth =
            new UsernamePasswordAuthenticationToken(
                "testuser",
                "password",
                authorities);

        strategy.doAddRole("projectRoles", "@AuthorizeByAuthority(builder, PATTERN_TEMPLATE)",
            "",
            "true", "^pipeline.*", "builder");

        strategy.doAssignUserRole("projectRoles", "@AuthorizeByAuthority(builder, PATTERN_TEMPLATE)", "testuser");
        SecurityContextHolder.getContext().setAuthentication(auth);

        assertThat("Has no build access to project ", project.hasPermission2(auth, Job.BUILD), equalTo(false));
    }


    /**
     * Test that wrong macro syntax does not give permission
    */
   
    @Test
    public void testPermissionTemplateWrongMacroSyntax() throws Exception {
        
        FreeStyleProject project = j.createFreeStyleProject("pipeline-test");

        RoleBasedAuthorizationStrategy strategy =  (RoleBasedAuthorizationStrategy)j.jenkins.getAuthorizationStrategy();
        strategy.doAddTemplate("builder",  "hudson.model.Item.Read,hudson.model.Item.Build", true);
        
        List<GrantedAuthority> authorities = List.of(
            new SimpleGrantedAuthority("test_builder")
        );

        JenkinsRule.DummySecurityRealm securityRealm = j.createDummySecurityRealm();
        j.jenkins.setSecurityRealm(securityRealm);
        j.jenkins.setAuthorizationStrategy(strategy);
        j.jenkins.setCrumbIssuer(null);
        
        Authentication auth =
            new UsernamePasswordAuthenticationToken(
                "testuser",
                "password",
                authorities);

        strategy.doAddRole("projectRoles", "@AuthorizeByAuthority(builder, WRONG_SYNTAX)",
            "",
            "true", "^pipeline.*", "builder");

        strategy.doAssignUserRole("projectRoles", "@AuthorizeByAuthority(builder, WRONG_SYNTAX)", "testuser");
        SecurityContextHolder.getContext().setAuthentication(auth);

        assertThat("Has no build access to project ", project.hasPermission2(auth, Job.BUILD), equalTo(false));
    }


    /**
     * Test that authorities with multiple separators are skipped
    */
   
    @Test
    public void testPermissionTemplateTemplateWithMultipleSeparators() throws Exception {
        
        FreeStyleProject project = j.createFreeStyleProject("pipeline-test");

        RoleBasedAuthorizationStrategy strategy =  (RoleBasedAuthorizationStrategy)j.jenkins.getAuthorizationStrategy();
        strategy.doAddTemplate("buil_der",  "hudson.model.Item.Read,hudson.model.Item.Build", true);
        
        List<GrantedAuthority> authorities = List.of(
            new SimpleGrantedAuthority("test_buil_der")
        );

        JenkinsRule.DummySecurityRealm securityRealm = j.createDummySecurityRealm();
        j.jenkins.setSecurityRealm(securityRealm);
        j.jenkins.setAuthorizationStrategy(strategy);
        j.jenkins.setCrumbIssuer(null);
        
        Authentication auth =
            new UsernamePasswordAuthenticationToken(
                "testuser",
                "password",
                authorities);

        strategy.doAddRole("projectRoles", "@AuthorizeByAuthority(buil_der, PATTERN_TEMPLATE)",
            "",
            "true", "^pipeline.*", "buil_der");

        strategy.doAssignUserRole("projectRoles", "@AuthorizeByAuthority(buil_der, PATTERN_TEMPLATE)", "testuser");
        SecurityContextHolder.getContext().setAuthentication(auth);

        assertThat("Has no build access to project ", project.hasPermission2(auth, Job.BUILD), equalTo(false));
    }

    /**
     * Test that user with wrong authority does not have template assigned using macro
    */
   
    @Test
    public void testPermissionTemplateNoProjectNameMatch() throws Exception {
        
        FreeStyleProject project = j.createFreeStyleProject("pipeline-internal");

        RoleBasedAuthorizationStrategy strategy =  (RoleBasedAuthorizationStrategy)j.jenkins.getAuthorizationStrategy();
        strategy.doAddTemplate("builder",  "hudson.model.Item.Read,hudson.model.Item.Build", true);
        
        List<GrantedAuthority> authorities = List.of(
            new SimpleGrantedAuthority("test_builder")
        );

        JenkinsRule.DummySecurityRealm securityRealm = j.createDummySecurityRealm();
        j.jenkins.setSecurityRealm(securityRealm);
        j.jenkins.setAuthorizationStrategy(strategy);
        j.jenkins.setCrumbIssuer(null);
        
        Authentication auth =
            new UsernamePasswordAuthenticationToken(
                "testuser",
                "password",
                authorities);

        strategy.doAddRole("projectRoles", "@AuthorizeByAuthority(builder, PATTERN_TEMPLATE)",
            "",
            "true", "^pipeline.*", "builder");

        strategy.doAssignUserRole("projectRoles", "@AuthorizeByAuthority(builder, PATTERN_TEMPLATE)", "testuser");
        SecurityContextHolder.getContext().setAuthentication(auth);

        assertThat("Has no build access to project ", project.hasPermission2(auth, Job.BUILD), equalTo(false));
    }


    /**
     * Test that user with wrong authority does not have template assigned using macro
    */
   
    @Test
    public void testPermissionTemplateMultipleAuthorities() throws Exception {
        
        FreeStyleProject project = j.createFreeStyleProject("pipeline-test");
        RoleBasedAuthorizationStrategy strategy =  (RoleBasedAuthorizationStrategy)j.jenkins.getAuthorizationStrategy();
        
        strategy.doAddTemplate("builder",  "hudson.model.Item.Read,hudson.model.Item.Build", true);
        strategy.doAddTemplate("configurer",  "hudson.model.Item.Read,hudson.model.Item.Configure", true);
        
        List<GrantedAuthority> authorities = List.of(
            new SimpleGrantedAuthority("test_builder"),
            new SimpleGrantedAuthority("test_configurer")

        );

        JenkinsRule.DummySecurityRealm securityRealm = j.createDummySecurityRealm();
        j.jenkins.setSecurityRealm(securityRealm);
        j.jenkins.setAuthorizationStrategy(strategy);
        j.jenkins.setCrumbIssuer(null);
        
        Authentication auth =
            new UsernamePasswordAuthenticationToken(
                "testuser",
                "password",
                authorities);

        strategy.doAddRole("projectRoles", "@AuthorizeByAuthority(builder, PATTERN_TEMPLATE)",
            "",
            "true", "^pipeline.*", "builder");
        strategy.doAddRole("projectRoles", "@AuthorizeByAuthority:1(configurer, PATTERN_TEMPLATE)",
            "",
            "true", "^pipeline.*", "configurer");

        strategy.doAssignUserRole("projectRoles", "@AuthorizeByAuthority(builder, PATTERN_TEMPLATE)", "testuser");
        strategy.doAssignUserRole("projectRoles", "@AuthorizeByAuthority:1(configurer, PATTERN_TEMPLATE)", "testuser");

        SecurityContextHolder.getContext().setAuthentication(auth);

        assertThat("Has build access to project from template ", project.hasPermission2(auth, Job.BUILD), equalTo(true));
        assertThat("Has configure access to project from template ", project.hasPermission2(auth, Job.CONFIGURE), equalTo(true));

    }
}
       
