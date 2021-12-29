package runwar.undertow;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.HashSet;
import java.util.List;
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
import io.undertow.server.handlers.resource.ResourceChangeEvent;
import io.undertow.server.handlers.resource.ResourceChangeListener;
import io.undertow.server.handlers.resource.ResourceManager;
import runwar.Server;
import runwar.Server.ServletDeployment;
import runwar.options.ServerOptions;
import io.undertow.servlet.handlers.ServletRequestContext;

import static runwar.logging.RunwarLogger.LOG;
import static runwar.logging.RunwarLogger.MAPPER_LOG;

/**
 * The host resource manager contains 1 or more actual resoruce managers inside, mapped to deploy keys.  When undertow needs to map a real path,
 * this resource manager will find and return the actual resoruce manager who's base path maps to the host/deployment key in the thread's current exchange.
 * 
 * @author Brad
 *
 */
public class HostResourceManager implements ResourceManager {

    private HashMap<String, ResourceManager> resourceManagers;

    /**
     * Create an instance.  A default resource manager is required
     * @param defaultResourceManager The default resource manager to use when the deploy key isn't found or doesn't match
     */
    public HostResourceManager( ResourceManager defaultResourceManager ) {
    	resourceManagers = new HashMap<String, ResourceManager>();
    	
    	addResourceManager( Server.ServletDeployment.DEFAULT, defaultResourceManager );
    }
    
    /**
     * Add a new resource manager that maps to a host/deploy key 
     * @param deploymentKey The key that should map to this resource manager
     * @param resourceManager The resource manager.  
     */
    public void addResourceManager( String deploymentKey, ResourceManager resourceManager ) {
    	resourceManagers.put(deploymentKey, resourceManager);
    }

    /**
     * Get the resource from the underlying resource manager matching the current deployment key in the exchange
     */
    @Override
    public Resource getResource(String path) throws IOException {
    	return getResourceManager().getResource( path );
    }

    /**
     * Find the resource manager that matches the deploy key in the exchange.
     * If there is no exchange, no deploy key, or an unrecognized deploy key, the default resource manager is returned. 
     * @return A resource manager.
     */
    public ResourceManager getResourceManager() {
    	HttpServerExchange exchange = null;
    	ResourceManager resourceManager = null;
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

    /**
     * Closes all the resource managers stored internall
     */
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

	/**
	 * Delegate to the current matching resource manager
	 */
    @Override
    public boolean isResourceChangeListenerSupported() {
        return getResourceManager().isResourceChangeListenerSupported();
    }

	/**
	 * Delegate to the current matching resource manager
	 */
    @Override
    public synchronized void registerResourceChangeListener(ResourceChangeListener listener) {
    	getResourceManager().registerResourceChangeListener( listener );
    }

	/**
	 * Delegate to the current matching resource manager
	 */
    @Override
    public synchronized void removeResourceChangeListener(ResourceChangeListener listener) {
    	getResourceManager().removeResourceChangeListener( listener );
    }


}
