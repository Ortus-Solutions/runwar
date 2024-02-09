package runwar.undertow;

import static runwar.logging.RunwarLogger.LOG;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.File;
import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

public class RewriteMap {

    private String name;
    private File mapFile;
    private Boolean caseSensitive;
    private Map<String,String> data;
    private long dataLastModified;

    public RewriteMap( String name, File mapFile, Boolean caseSensitive ) throws Exception {
        this.name = name;
        this.mapFile = mapFile;
        this.caseSensitive = caseSensitive;
        loadData();
    }

    public String getName() {
        return name;
    }

    // For debugging
    public Map<String,String> getData() {
        return data;
    }

    public String getKey( String key ) {
        if( key == null ) {
            return null;
        }
        if( !caseSensitive ) {
            key = key.toLowerCase();
        }
        return data.get( key );
    }

    public Boolean keyExists( String key ) {
        if( key == null ) {
            return false;
        }
        if( !caseSensitive ) {
            key = key.toLowerCase();
        }
        return data.containsKey( key );
    }

    public String getKey( String key, String defaultValue ) {
        String value = getKey( key );
        if( value == null ) {
            return defaultValue;
        }
        return value;
    }

    public void checkReload() {
        if( isDataStale() ) {
            synchronized( this ) {
                if( isDataStale() ) {
                    loadData();
                }
            }
        }
    }

    private void loadData() {
        Map<String,String> newData = new ConcurrentHashMap<String,String>();
		BufferedReader reader;

		try {
			reader = new BufferedReader(new FileReader(mapFile));
			String line;

			while ( ( line = reader.readLine() ) != null) {
                if( line.startsWith( "#" ) || line.isEmpty() ) {
                    continue;
                }

				String[] tokens = line.trim().split( "\\s+", 2 );
                String key = tokens[0];
                if( !caseSensitive ) {
                    key = key.toLowerCase();
                }
                if( tokens.length == 1 ) {
                    newData.put( key, "" );
                } else {
                    newData.put( key, tokens[1] );
                }
			}

			reader.close();
		} catch (IOException e) {
			throw new RuntimeException( "Error reading Rewrite Map file [" + mapFile.toString() + "]", e );
		}

        // Do swap, so there is always data
        data = newData;
        dataLastModified = mapFile.lastModified();
    }

    private Boolean isDataStale() {
        return mapFile.lastModified() != dataLastModified;
    }

}