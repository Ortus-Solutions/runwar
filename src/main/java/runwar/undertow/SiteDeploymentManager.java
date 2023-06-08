package runwar.undertow;


import io.undertow.Handlers;
import io.undertow.Undertow;
import io.undertow.Undertow.Builder;
import io.undertow.client.ClientConnection;
import io.undertow.UndertowOptions;
import io.undertow.predicate.Predicates;
import io.undertow.predicate.Predicate;
import io.undertow.server.DefaultByteBufferPool;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.PathHandler;
import io.undertow.server.handlers.ProxyPeerAddressHandler;
import io.undertow.server.handlers.SSLHeaderHandler;
import io.undertow.server.handlers.accesslog.AccessLogHandler;
import io.undertow.server.handlers.accesslog.DefaultAccessLogReceiver;
import io.undertow.server.handlers.builder.PredicatedHandler;
import io.undertow.server.handlers.builder.PredicatedHandlersParser;
import io.undertow.server.handlers.cache.DirectBufferCache;
import io.undertow.server.handlers.encoding.ContentEncodingRepository;
import io.undertow.server.handlers.encoding.EncodingHandler;
import io.undertow.server.handlers.encoding.GzipEncodingProvider;
import io.undertow.server.handlers.resource.CachingResourceManager;
import io.undertow.server.handlers.resource.ResourceManager;
import io.undertow.server.handlers.resource.ResourceHandler;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.DeploymentManager;
import io.undertow.servlet.api.ServletSessionConfig;
import io.undertow.util.CanonicalPathUtils;
import io.undertow.util.AttachmentKey;
import io.undertow.util.HeaderValues;
import io.undertow.server.handlers.resource.Resource;
import io.undertow.util.Headers;
import io.undertow.util.HttpString;
import io.undertow.util.MimeMappings;
import io.undertow.io.Sender;
import io.undertow.websockets.jsr.WebSocketDeploymentInfo;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.xnio.*;
import runwar.logging.LoggerFactory;
import runwar.logging.LoggerPrintStream;
import runwar.logging.RunwarAccessLogReceiver;
import runwar.mariadb4j.MariaDB4jManager;
import runwar.options.ServerOptions;
import runwar.options.SiteOptions;
import runwar.options.ConfigParser.JSONOption;
import runwar.security.SSLUtil;
import runwar.security.SecurityManager;
import runwar.tray.Tray;
import runwar.undertow.MappedResourceManager;
import runwar.undertow.HostResourceManager;
import runwar.undertow.RequestDebugHandler;
import runwar.undertow.SSLClientCertHeaderHandler;
import runwar.undertow.LifecyleHandler;
import runwar.undertow.WelcomeFileHandler;
import runwar.undertow.SiteDeployment;
import runwar.undertow.SiteDeploymentManager;
import runwar.util.ClassLoaderUtils;
import runwar.util.RequestDumper;
import runwar.util.MaxContextsException;
import runwar.RunwarConfigurer;
import runwar.Server;

import javax.net.ssl.SSLContext;
import java.awt.*;
import java.io.*;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Method;
import java.net.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.*;
import javax.servlet.Servlet;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.ServletRequest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.undertow.servlet.Servlets.defaultContainer;
import static io.undertow.servlet.Servlets.deployment;
import io.undertow.servlet.handlers.ServletRequestContext;
import io.undertow.server.HandlerWrapper;

import static runwar.logging.RunwarLogger.LOG;
import static runwar.logging.RunwarLogger.MAPPER_LOG;

@SuppressWarnings( "deprecation" )
public class SiteDeploymentManager {

    public static final AttachmentKey<String> DEPLOYMENT_KEY = AttachmentKey.create(String.class);
    public static final AttachmentKey<SiteDeployment> SITE_DEPLOYMENT_KEY = AttachmentKey.create(SiteDeployment.class);

    private ConcurrentHashMap<String,SiteDeployment> deployments = new ConcurrentHashMap<String,SiteDeployment>();
    private SiteDeployment adobeDefaultDeployment=null;
    private ServerOptions serverOptions;

    public SiteDeploymentManager( ServerOptions serverOptions ) throws Exception {
        this.serverOptions = serverOptions;
    }

    public ConcurrentHashMap<String,SiteDeployment> getDeployments() {
        return deployments;
    }

    public synchronized SiteDeployment createSiteDeployment( DeploymentInfo servletBuilder, File webroot, RunwarConfigurer configurer, String deploymentKey, String vDirs, SiteOptions siteOptions ) throws Exception {
    	SiteDeployment deployment;

    	// If another thread already created this deployment
    	if( ( deployment = deployments.get( deploymentKey ) ) != null ) {
    		return deployment;
    	}

    	if( deployments.size() > serverOptions.autoCreateContextsMax() ) {
    		throw new MaxContextsException( "Cannot create new servlet deployment.  The configured max is [" + serverOptions.autoCreateContextsMax() + "]." );
    	}

        LOG.info("Creating deployment [" + deploymentKey + "]" );

    	File webInfDir = serverOptions.webInfDir();
        Long transferMinSize= siteOptions.transferMinSize();
        Map<String,Path> aliases = new HashMap<>();
        siteOptions.aliases().forEach((s, s2) -> aliases.put(s,Paths.get(s2)));

        // Add any web server VDirs to Undertow. They come in this format:
        // /foo,C:\path\to\foo;/bar,C:\path\to\bar
        if( vDirs != null && !vDirs.isEmpty() ) {
        	// Parsing logic borrowed from mod_cfml source:
        	// https://github.com/paulklinkenberg/mod_cfml/blob/32e1fd868d7698f91ad12cffcaeb17258b4071d8/java/mod_cfml-valve/src/mod_cfml/core.java#L409-L420
			String[] aVDirs = vDirs.split(";");
			for (int i=0; i<aVDirs.length; i++) {
				String[] dirParts = aVDirs[i].split(",");
				if (dirParts.length == 2 && dirParts[0].length() > 1 && dirParts[1].length() > 1) {
					// windows paths to forward slash
					dirParts[1] = dirParts[1].replace("\\", "/");
					if( !aliases.containsKey( dirParts[0] ) ) {
						aliases.put( dirParts[0], Paths.get( dirParts[1] ) );
					}
				}
			}
        }

        ResourceManager resourceManager = getResourceManager(webroot, transferMinSize, aliases, webInfDir, siteOptions);
        try {
            Server.setCurrentDeploymentKey( deploymentKey );

            // For non=Adobe (Lucee), create actual servlet context
            if( serverOptions.cfEngineName().toLowerCase().indexOf("adobe") == -1 ) {
                servletBuilder.setResourceManager(resourceManager);
                DeploymentManager manager = defaultContainer().addDeployment(servletBuilder);
                manager.deploy();

                deployment = new SiteDeployment( manager.start(), manager, siteOptions, serverOptions, resourceManager );
                LOG.debug("  New servlet context created for [" + deploymentKey + "]" );
            // For Adobe
            } else {
                // For first deployment, create initial resource manager and deploy
                if( deployments.size() == 0 ) {
                    ResourceManager hostResourceManager = new HostResourceManager( resourceManager );
                    servletBuilder.setResourceManager( hostResourceManager );
                    DeploymentManager manager = defaultContainer().addDeployment(servletBuilder);
                    manager.deploy();
                    deployment = new SiteDeployment( manager.start(), manager, siteOptions, serverOptions, hostResourceManager );
                    this.adobeDefaultDeployment = deployment;
                    LOG.debug("  Initial servlet context created for [" + deploymentKey + "]" );

                // For all subsequent deploys, reuse default deployment and simply add new resource manager
                } else {

                    ((HostResourceManager)servletBuilder.getResourceManager()).addResourceManager( deploymentKey, resourceManager );
                    // Create a new deployment and site handler chain that calls the same servlet initial handler
                    deployment = new SiteDeployment( this.adobeDefaultDeployment.getServletInitialHandler(), this.adobeDefaultDeployment.getDeploymentManager(), siteOptions, serverOptions, this.adobeDefaultDeployment.getResourceManager() );
                    LOG.debug("  Cloned servlet context added for deployment [" + deploymentKey + "]" );

                }
            }
        } finally {
            Server.setCurrentDeploymentKey( null );
        }

    	deployments.put(deploymentKey, deployment);

    	return deployment;
    }

    public ResourceManager getResourceManager(File warFile, Long transferMinSize, Map<String, Path> aliases, File internalCFMLServerRoot, SiteOptions siteOptions) {
    	Boolean cached = siteOptions.cacheServletPaths();

        LOG.debugf("  Initialized " + ( cached ? "CACHED " : "" ) + "MappedResourceManager" );
        LOG.infof("    Web Root: %s", warFile.getAbsolutePath() );
        if( aliases.size() > 0 ) {
            LOG.debugf("    Aliases: %s", aliases );
        }

        MappedResourceManager mappedResourceManager = new MappedResourceManager(warFile, transferMinSize, aliases, internalCFMLServerRoot, siteOptions);
        if ( !cached ) {
            return mappedResourceManager;
        }

        LOG.debugf("  ResourceManager Cache total size: %s MB", siteOptions.fileCacheTotalSizeMB() );
        LOG.debugf("  ResourceManager Cache max file size: %s KB", siteOptions.fileCacheMaxFileSizeKB() );

        // 8 hours in in milliseconds-- used for both the path metadata cache AND the file contents cache
        // Setting to -1 will never expire items from the cache, which is tempting-- but having some sort of expiration will keep errant entries from clogging the cache forever
        int METADATA_MAX_AGE = 8 * 60 * 60 * 1000;
        /* DirectBufferCache.sliceSize: internally DirectBufferCache has a buffer pool. This pool is responsible for allocating byte buffers to store the data that is in the cache,
         * the size of those buffers will be sliceSize * slicesPerPage. Each byte buffer region that is allocated in the memory is split into slicesPerPage, and then each buffer
         *  will have sliceSize. To give you an example, if you have 50 slicesPerPage and each one is 10,000 bytes long (this would be sliceSize), each time a buffer is needed,
         *  it allocates a region whose size is 500,000 bytes. That region is split into 50 byte buffers of length 10,000 (in bytes).
         *  If those buffers are all used at some point and not reclaimed, when the pool needs more buffers, it will allocate another 500,000 bytes long chunk, and so on, but there is a limit to it,
         *  which is maxMemory
         */
        // Max file size to cache directly in memory-- measured in bytes.
        final long maxFileSize = siteOptions.fileCacheMaxFileSizeKB() * 1024; // Convert KB to B
        /* DirectBufferCache.maxMemory: this is the maximum number of bytes that can be allocated by the pool. So, in the example above, supposed that slicesPerPage is 50, and sliceSize is 10,000 bytes,
         * if you have a maxMemory of 1,000,000 bytes, it means that the buffer pool can only allocate two chunks of 500,000 bytes each, because that's the number of 500,000 bytes long
         * regions that fit into 1,000,000. If none of those buffers are reclaimed at some point, and more buffers are needed, the buffer pool will refuse to do more allocations.
         * The cache will remove the oldest entry from usage pov because it is LRU. This cache is used by CachingResourceManager to store contents of files in direct memory. */
        int maxMemory = siteOptions.fileCacheTotalSizeMB() * 1024 * 1024; // Convert MB to B
        // Number of paths to cache. i.e. /foo.txt maps to C:/webroot/foo.txt
        // I assume the memory overhead of the meta is nearly zero since it's just a single POJO instance per path
        final int metadataCacheSize = 10000;
        if( maxMemory > 0 && maxFileSize > 0 ) {
            int sliceSize = 1024 * 1024; // 1 KB per slice
            // DirectBufferCache slicesPerPage: the explanation is right above.
            int slicesPerPage = 10; // 10 slices per page means 10 KB per buffer
            final DirectBufferCache dataCache = new DirectBufferCache(sliceSize, slicesPerPage, maxMemory, BufferAllocator.DIRECT_BYTE_BUFFER_ALLOCATOR, METADATA_MAX_AGE);

            return new CachingResourceManager(metadataCacheSize, maxFileSize, dataCache, mappedResourceManager, METADATA_MAX_AGE);
        } else {
        	LOG.debug("  ResourceManager file cache disabled since size is zero. Path lookups will still be cached." );
            return new CachingResourceManager(metadataCacheSize, maxFileSize, null, mappedResourceManager, METADATA_MAX_AGE);
        }
    }

}