package runwar.undertow;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
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

import io.undertow.server.handlers.resource.FileResource;
import io.undertow.server.handlers.resource.FileResourceManager;
import io.undertow.server.handlers.resource.PathResourceManager;
import io.undertow.server.handlers.resource.Resource;
import io.undertow.server.handlers.resource.ResourceChangeEvent;
import io.undertow.server.handlers.resource.ResourceChangeListener;
import runwar.options.ServerOptions;



import org.xnio.FileChangeCallback;
import org.xnio.FileChangeEvent;
import org.xnio.FileSystemWatcher;
import org.xnio.OptionMap;
import org.xnio.Xnio;

import static runwar.logging.RunwarLogger.MAPPER_LOG;

public class MappedResourceManager extends FileResourceManager {

    private ServerOptions serverOptions;
    private Boolean forceCaseSensitiveWebServer;
    private Boolean forceCaseInsensitiveWebServer;
    private HashMap<String, Path> aliases;
    private File WEBINF = null, CFIDE = null;
    private static boolean isCaseSensitiveFS = caseSensitivityCheck();
    private static final Pattern CFIDE_REGEX_PATTERN;
    private static final Pattern WEBINF_REGEX_PATTERN;
    private final FileResource baseResource;

    // testing
    private final List<ResourceChangeListener> listeners = new ArrayList<>();
    private List<FileSystemWatcher> fileSystemWatchers = new ArrayList<>();

    static {
        CFIDE_REGEX_PATTERN = Pattern.compile("(?i)^[\\\\/]?CFIDE([\\\\/].*)?");
        WEBINF_REGEX_PATTERN = Pattern.compile("(?i)^[\\\\/]?WEB-INF([\\\\/].*)?");
   }

    private final boolean allowResourceChangeListeners;

    public MappedResourceManager(File base, long transferMinSize, Map<String,Path> aliases, File webinfDir, ServerOptions serverOptions) {
        super(base, transferMinSize);
        this.allowResourceChangeListeners = serverOptions.resourceManagerFileSystemWatcher();
        if( !this.allowResourceChangeListeners ) {
            MAPPER_LOG.debug("Resource change listener disabled for [" + base.toString() + "]");
        }
        this.aliases = (HashMap<String, Path>) aliases;
        this.serverOptions = serverOptions;
        this.forceCaseSensitiveWebServer = serverOptions.caseSensitiveWebServer() != null && serverOptions.caseSensitiveWebServer();
        this.forceCaseInsensitiveWebServer = serverOptions.caseSensitiveWebServer() != null && !serverOptions.caseSensitiveWebServer();
        this.baseResource = new FileResource( getBase(), this, "/");

        if(webinfDir != null){
            WEBINF = webinfDir;
            CFIDE = new File(WEBINF.getParentFile(),"CFIDE");
            if (!WEBINF.exists()) {
                throw new RuntimeException("The specified WEB-INF does not exist: " + WEBINF.getAbsolutePath());
            }
        }
    }

    public Resource getResource(String path) {
        if(path == null) {
            MAPPER_LOG.error("* getResource got a null path!");
            return null;
        }
        MAPPER_LOG.debug("* requested: '" + path + "'");

        if( path.equals( "/" ) ) {
        	MAPPER_LOG.debugf("** path mapped to: '%s'", getBase());
            return this.baseResource;
        }


        try {
	        Path reqFile = null;
	        final Matcher webInfMatcher = WEBINF_REGEX_PATTERN.matcher(path);
	        final Matcher cfideMatcher = CFIDE_REGEX_PATTERN.matcher(path);
	        if (WEBINF != null && webInfMatcher.matches()) {
	            if(webInfMatcher.group(1) == null) {
	                reqFile = Paths.get(WEBINF.toURI());
	            } else {
	                reqFile = Paths.get(WEBINF.getAbsolutePath(), webInfMatcher.group(1).replace("WEB-INF", ""));
	            }
	            MAPPER_LOG.trace("** matched WEB-INF : " + reqFile.toAbsolutePath().toString());
                reqFile = pathExists(reqFile);
	        } else if (cfideMatcher.matches()) {
	            if(cfideMatcher.group(1) == null) {
	                reqFile = Paths.get(CFIDE.toURI());
	            } else {
	                reqFile = Paths.get(CFIDE.getAbsolutePath(), cfideMatcher.group(1).replace("CFIDE", ""));
	            }
	            MAPPER_LOG.trace("** matched /CFIDE : " + reqFile.toAbsolutePath().toString());
                reqFile = pathExists(reqFile);
	        } else if (!webInfMatcher.matches()) {
	            reqFile = Paths.get(getBase().getAbsolutePath(), path);
	            MAPPER_LOG.trace("* checking with base path: '" + reqFile.toAbsolutePath().toString() + "'");
                reqFile = pathExists(reqFile);
	            if ( reqFile == null ) {
	                reqFile = getAliasedFile(aliases, path);
                    if (reqFile != null ) {
                        reqFile = pathExists(reqFile);
                    }
	            }
	        }

	        if (reqFile == null ) {
 	           MAPPER_LOG.debugf( "** No real resource found on disk for: '%s'", path );
 	           return null;
	        }

            if(reqFile.toString().indexOf('\\') > 0) {
                reqFile = Paths.get(reqFile.toString().replace('/', '\\'));
            }

            // Check for Windows doing silly things with file canonicalization
            String originalPath = reqFile.toString();

            // The real path will return the actual file on the file system that is matched
            // the original path may be in the wrong case and may have extra junk on the end that Windows removes when it canonicalizes
            String realPath = reqFile.toRealPath(LinkOption.NOFOLLOW_LINKS).toString();
            String originalPathCase;
            String realPathCase;

            // If this is a case insensitive file system like Windows and we're not forcing the web server to be case sensitive
            // then compare the paths regardless of case.  Or if this is a case sensitive file system like Linux
            // and we're forcing it to be case insensitive
            if( (!isCaseSensitiveFS && !forceCaseSensitiveWebServer) || ( isCaseSensitiveFS && forceCaseInsensitiveWebServer ) ) {
            	originalPathCase = originalPath.toLowerCase();
            	realPathCase = realPath.toLowerCase();
            // For case sensitive file systems like Linux OR if we're forcing the web server to be case sensitive
            // compare the real path exactly
            } else {
            	originalPathCase = originalPath;
            	realPathCase = realPath;
            }

            // make sure the path we found on the file system matches what was asked for.
            if( !originalPathCase.equals( realPathCase ) ) {
            	throw new InvalidPathException( "Real file path [" + realPath + "] doesn't match [" + originalPath + "]", "" );
            }

            MAPPER_LOG.debugf("** path mapped to real file: '%s'", reqFile);
	        return new FileResource(reqFile.toFile(), this, path);

        } catch( InvalidPathException e ){
            MAPPER_LOG.debugf("** InvalidPathException for: '%s'",path != null ? path : "null");
            MAPPER_LOG.debug("** " + e.getMessage());
            return null;
        } catch( IOException e ){
            MAPPER_LOG.debugf("** IOException for: '%s'",path != null ? path : "null");
            MAPPER_LOG.debug("** " + e.getMessage());
            return null;
        }
    }

    static Path getAliasedFile(HashMap<String, Path> aliasMap, String path) {
        if(path.startsWith("/file:")){
            // groovy servlet asks for /file:... for some reason, when scripts are in an aliased dir
            path = path.replace("/file:", "");
            for( Path file : aliasMap.values()) {
                if(path.startsWith(file.toAbsolutePath().toString())) {
    	            MAPPER_LOG.trace("** Path is exact match for alias: '" + file.toAbsolutePath().toString() + "'");
                    return Paths.get(path);
                }
            }
        }

        String pathDir = path.startsWith("/") ? path : "/" + path;
        Path file = aliasMap.get(pathDir.toLowerCase());
        if(file != null) {
            return file;
        }
        while (pathDir.lastIndexOf('/') > 0) {
            pathDir = pathDir.substring(0, pathDir.lastIndexOf('/'));
            if (aliasMap.containsKey(pathDir.toLowerCase())) {
                file = Paths.get(aliasMap.get(pathDir.toLowerCase()).toString() + '/' + path.substring(pathDir.length())).normalize();
                if(file.toString().indexOf('\\') > 0){
                    file = Paths.get(file.toString().replace('/', '\\'));
                }
                MAPPER_LOG.trace("** Path is matched inside alias: '" + pathDir.toLowerCase() + "'");
                return file;
            }
        }
        return null;
    }

    Path pathExists(Path path) {
       Boolean defaultCheck = Files.exists( path );
       if( defaultCheck ) {
           return path;
       }
       if( isCaseSensitiveFS && forceCaseInsensitiveWebServer ) {
            MAPPER_LOG.debugf("*** Case insensitive check for %s",path);

        	String realPath = "";
        	String[] pathSegments = path.toString().replace('\\', '/').split( "/" );
        	if( pathSegments.length > 0 && pathSegments[0].contains(":") ){
        		realPath = pathSegments[0];
        	}
        	Boolean first = true;
        	for( String thisSegment : pathSegments ) {
        		// Skip windows drive letter
        		if( realPath == pathSegments[0] && pathSegments[0].contains(":") && first ) {
            		first = false;
        			continue;
        		}
        		// Skip empty segments
        		if( thisSegment.length() == 0 ) {
        			continue;
        		}

        		Boolean found = false;
        		String[] children = new File( realPath + "/" ).list();
        		// This will happen if we have a matched file in the middle of a path like /foo/index.cfm/bar
        		if( children == null ) {
        			return null;
        		}
        		for( String thisChild : children ) {
        			// We're taking the FIRST MATCH.  Buyer beware
        			if( thisSegment.equalsIgnoreCase(thisChild)) {
        				realPath += "/" + thisChild;
        				found = true;
        				break;
        			}
        		}
    			// If we made it through the inner loop without a match, we've hit a dead end
        		if( !found ) {
        			return null;
        		}
        	}
			// If we made it through the outer loop, we've found a match
        	Path realPathFinal = Paths.get( realPath );
        	return realPathFinal;
      }
      return null;
    }

    HashMap<String, Path> getAliases() {
        return aliases;
    }

    @Override
    public boolean isResourceChangeListenerSupported() {
        return allowResourceChangeListeners;
    }

    private static boolean caseSensitivityCheck() {
	    try {
	        File currentWorkingDir = new File(System.getProperty("user.home"));
	        File case1 = new File(currentWorkingDir, "case1");
	        File case2 = new File(currentWorkingDir, "Case1");
            MAPPER_LOG.debug("Testing case sensitivity of file system by writing to [" + case1.toString() + "]");
	        case1.createNewFile();
	        if (case2.createNewFile()) {
	        	MAPPER_LOG.debug("FileSystem of working directory is case sensitive");
	            case1.delete();
	            case2.delete();
	            return true;
	        } else {
	        	MAPPER_LOG.debug("FileSystem of working directory is NOT case sensitive");
	            case1.delete();
	            return false;
	        }
	    } catch (Throwable e) {
	    	MAPPER_LOG.debug("Error detecting case sensitivity of file system.");
	    	e.printStackTrace();
	    }
        return true;
	}

    public synchronized void registerResourceChangeListener(ResourceChangeListener listener) {
        if(!allowResourceChangeListeners) {
            //by rights we should throw an exception here, but this works around a bug in Wildfly where it just assumes
            //PathResourceManager supports this. This will be fixed in a later version
            return;
        }
    	MAPPER_LOG.trace("Adding change listener for mapped resource manager");
        if (!fileSystem.equals(FileSystems.getDefault())) {
            throw new IllegalStateException("Resource change listeners not supported when using a non-default file system");
        }
        listeners.add(listener);
        if (fileSystemWatchers.isEmpty()) {
            fileSystemWatchers.add( createFileSystemWatcher( base, "" ) );
            if( WEBINF != null ){
                fileSystemWatchers.add( createFileSystemWatcher( WEBINF.getAbsolutePath(), "/WEB-INF" ) );
            }
            if( CFIDE != null && CFIDE.exists() ){
                fileSystemWatchers.add( createFileSystemWatcher( CFIDE.getAbsolutePath(), "/CFIDE" ) );
            }
            aliases.forEach( (alias,path) -> {
            	// In case there is a broken alias pointing nowhere
            	if(  Files.exists( path ) ) {
                	createFileSystemWatcher( path.toString(), alias );
            	}
            } );

        }
    }

    FileSystemWatcher createFileSystemWatcher( String basePath, String prefix ) {

    	MAPPER_LOG.trace("Creating file system watcher in [ " + basePath + " ] with alias [ " + prefix + " ]");

    	final String thePrefix;
    	if( prefix.startsWith("/") ) {
    		thePrefix = prefix.substring(1);
    	} else {
    		thePrefix = prefix;
    	}

    	FileSystemWatcher fileSystemWatcher = Xnio.getInstance().createFileSystemWatcher("Watcher for " + basePath, OptionMap.EMPTY);
        fileSystemWatcher.watchPath(new File(basePath), new FileChangeCallback() {
            @Override
            public void handleChanges(Collection<FileChangeEvent> changes) {
                synchronized (MappedResourceManager.this) {
                    final List<ResourceChangeEvent> events = new ArrayList<>();
                    for (FileChangeEvent change : changes) {
                        if (change.getFile().getAbsolutePath().startsWith(basePath)) {
                            String path = change.getFile().getAbsolutePath().substring(basePath.length());
                            if (File.separatorChar == '\\' && path.contains(File.separator)) {
                                path = path.replace(File.separatorChar, '/');
                            }
                            if( !thePrefix.isEmpty() ) {
                            	if( path.startsWith("/") ) {
                                    path = path.substring(1);
                            	}
                            	if( thePrefix.endsWith("/") ) {
                            		path = thePrefix + path;
                            	} else {
                            		path = thePrefix + "/" + path;
                            	}
                            }
                            events.add(new ResourceChangeEvent( path, ResourceChangeEvent.Type.valueOf(change.getType().name())));
                        }
                    }
                    for (ResourceChangeListener listener : listeners) {
                        listener.handleChanges(events);
                    }
                }
            }
        });
        return fileSystemWatcher;
    }

    @Override
    public synchronized void removeResourceChangeListener(ResourceChangeListener listener) {
        if(!allowResourceChangeListeners) {
            return;
        }
        listeners.remove(listener);
        super.removeResourceChangeListener(listener);
    }

    public synchronized void close() throws IOException {
    	fileSystemWatchers.forEach(w -> {
    		try {
				w.close();
			} catch (Exception e) {
				e.printStackTrace();
			}
    	} );
        super.close();
    }

}
