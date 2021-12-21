package runwar.undertow;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.Optional;

import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.resource.FileResource;
import io.undertow.server.handlers.resource.FileResourceManager;
import io.undertow.server.handlers.resource.Resource;
import io.undertow.server.handlers.resource.ResourceChangeListener;
import io.undertow.server.handlers.resource.ResourceManager;
import runwar.Server;
import runwar.Server.ServletDeployment;
import runwar.options.ServerOptions;
import io.undertow.servlet.handlers.ServletRequestContext;

import static runwar.logging.RunwarLogger.LOG;
import static runwar.logging.RunwarLogger.MAPPER_LOG;

public class HostResourceManager implements ResourceManager {

    private HashMap<String, MappedResourceManager> resourceManagers;
    private final boolean allowResourceChangeListeners;

    public HostResourceManager( MappedResourceManager defaultResourceManager ) {
    	allowResourceChangeListeners = false;
    	resourceManagers = new HashMap<String, MappedResourceManager>();
    	
    	addResourceManager( Server.ServletDeployment.DEFAULT, defaultResourceManager );
    }

    public void addResourceManager( String deploymentKey, MappedResourceManager resourceManager ) {
    	resourceManagers.put(deploymentKey, resourceManager);
    }
    
    public Resource getResource(String path) {
    	return getResourceManager().getResource( path );
    }

    public MappedResourceManager getResourceManager() {
    	HttpServerExchange exchange = null;
    	MappedResourceManager resourceManager = null;
    	String deploymentKey = null;
    	exchange = Server.getCurrentExchange();
    	
    	if( exchange != null ) {
            deploymentKey = exchange.getAttachment(Server.DEPLOYMENT_KEY);
            if( deploymentKey != null ) {
                MAPPER_LOG.debug("Current exchange's deploymentKey is: " + deploymentKey );
        	}
    	}

        if( deploymentKey == null ) {
        	deploymentKey = Server.ServletDeployment.DEFAULT;
    	}
        
    	resourceManager = resourceManagers.get( deploymentKey );
    	if( resourceManager != null ) {
    		return resourceManager;
    	} else {
    		return resourceManagers.get( Server.ServletDeployment.DEFAULT );
    	}
   
    }

    @Override
    public boolean isResourceChangeListenerSupported() {
        return allowResourceChangeListeners;
    }

	@Override
	public void close() throws IOException {
		resourceManagers.forEach((s, s2) -> {
			try {
				s2.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
		} );
	}

	@Override
	public void registerResourceChangeListener(ResourceChangeListener listener) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void removeResourceChangeListener(ResourceChangeListener listener) {
		// TODO Auto-generated method stub
		
	}

}
