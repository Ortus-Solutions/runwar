package runwar.undertow;

import static io.undertow.servlet.Servlets.deployment;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;

import io.undertow.servlet.api.ServletSessionConfig;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import io.undertow.server.session.InMemorySessionManager;
import io.undertow.server.session.SessionAttachmentHandler;
import io.undertow.server.session.SessionCookieConfig;
import io.undertow.servlet.api.DeploymentInfo;
import lucee.loader.servlet.CFMLServlet;

public class WebXMLParserTest {
    private DeploymentInfo deploymentInfo;

    public WebXMLParserTest() {
        deploymentInfo = deployment()
                .setContextPath("")
                .setServletSessionConfig(new ServletSessionConfig())
                .setTempDir(new File(System.getProperty("java.io.tmpdir")))
                .setDeploymentName("test").setClassLoader(this.getClass().getClassLoader());
    }

    @BeforeAll
    public static void before(){
//        LogSubverter.subvertLoggers("TRACE");
    }

    @Test
    public void testCommandBoxLuceeWebXML() {
        File webinf = new File("src/test/resources/xml/cmdbox");
        File webxml = new File(webinf, "lucee4.web.xml");
        boolean ignoreWelcomePages = false;
        boolean ignoreRestMappings = false;
        WebXMLParser.parseWebXml(webxml, webinf, deploymentInfo, ignoreWelcomePages, ignoreRestMappings);
        assertEquals(2, deploymentInfo.getServlets().size());
    }

    @Test
    public void testSpecialCharInPath() {
        File webinf = new File("src/test/resources/directorypaths/dollar$ign");
        File webxml = new File(webinf, "web.xml");
        boolean ignoreWelcomePages = false;
        boolean ignoreRestMappings = false;
        WebXMLParser.parseWebXml(webxml, webinf, deploymentInfo, ignoreWelcomePages, ignoreRestMappings);
        assertEquals(2, deploymentInfo.getServlets().size());
    }

    @Test
    public void testDefaultWebXml() {
        File webinf = new File("src/test/resources/xml");
        File webxml = new File(webinf, "web.xml");
        boolean ignoreWelcomePages = false;
        boolean ignoreRestMappings = false;
        assertFalse(deploymentInfo.getServletSessionConfig().isSecure());
        assertFalse(deploymentInfo.getServletSessionConfig().isHttpOnly());
        WebXMLParser.parseWebXml(webxml, webinf, deploymentInfo, ignoreWelcomePages, ignoreRestMappings);
        assertEquals(2, deploymentInfo.getServletContextAttributes().size());
        assertEquals(2, deploymentInfo.getServlets().size());
        assertEquals(5, deploymentInfo.getWelcomePages().size());
        assertEquals(6, deploymentInfo.getErrorPages().size());
        assertEquals(2, deploymentInfo.getMimeMappings().size());
        assertTrue(deploymentInfo.getServletSessionConfig().isSecure());
        assertTrue(deploymentInfo.getServletSessionConfig().isHttpOnly());
    }


}
