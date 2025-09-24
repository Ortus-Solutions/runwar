package runwar.undertow;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import runwar.undertow.handler.FrameworkRewritesBuilder;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class FrameworkRewritesBuilderTest {

    @Test
    @DisplayName("Should support rewriteFile parameter")
    void shouldSupportRewriteFileParameter() {
        FrameworkRewritesBuilder builder = new FrameworkRewritesBuilder();
        
        // Test that parameters() method returns rewriteFile parameter
        Map<String, Class<?>> parameters = builder.parameters();
        assertNotNull(parameters);
        assertTrue(parameters.containsKey("rewriteFile"));
        assertEquals(String.class, parameters.get("rewriteFile"));
    }

    @Test
    @DisplayName("Should have correct name")
    void shouldHaveCorrectName() {
        FrameworkRewritesBuilder builder = new FrameworkRewritesBuilder();
        assertEquals("framework-rewrite", builder.name());
    }

    @Test
    @DisplayName("Should have no required parameters")
    void shouldHaveNoRequiredParameters() {
        FrameworkRewritesBuilder builder = new FrameworkRewritesBuilder();
        assertTrue(builder.requiredParameters().isEmpty());
    }

    @Test
    @DisplayName("Should create handler wrapper with default rewrite file")
    void shouldCreateHandlerWrapperWithDefaultRewriteFile() {
        FrameworkRewritesBuilder builder = new FrameworkRewritesBuilder();
        Map<String, Object> config = new HashMap<>();
        
        // Should not throw an exception when building without rewriteFile parameter
        assertDoesNotThrow(() -> {
            builder.build(config);
        });
    }

    @Test
    @DisplayName("Should create handler wrapper with custom rewrite file")
    void shouldCreateHandlerWrapperWithCustomRewriteFile() {
        FrameworkRewritesBuilder builder = new FrameworkRewritesBuilder();
        Map<String, Object> config = new HashMap<>();
        config.put("rewriteFile", "app.cfm");
        
        // Should not throw an exception when building with rewriteFile parameter
        assertDoesNotThrow(() -> {
            builder.build(config);
        });
    }
}