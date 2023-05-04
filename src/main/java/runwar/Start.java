package runwar;

import io.undertow.Undertow;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.ResponseCodeHandler;
import io.undertow.server.handlers.proxy.LoadBalancingProxyClient;
import io.undertow.server.handlers.proxy.ProxyHandler;
import io.undertow.util.Headers;

import java.io.File;
import java.net.Socket;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;


import java.net.URLDecoder;

import runwar.logging.LoggerFactory;
import runwar.logging.RunwarLogger;
import runwar.options.ConfigParser;
import runwar.options.ServerOptions;

public class Start {


    // for openBrowser
	public Start(int seconds) {
	    new Server(seconds);
	}

	public static void main(String[] args) throws Exception {
        ServerOptions serverOptions;
        if(args.length == 1 ) {
            serverOptions = new ConfigParser(new File(args[0])).getServerOptions();
        } else {
            throw new RuntimeException( "Runwar must be called with a valid path to the serverinfo.json file as the only arg" );
        }

        Server server = new Server();
        try {
            server.startServer(serverOptions);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }

	}

    public static boolean serverListening(String host, int port) {
        Socket s = null;
        try {
            s = new Socket(host, port);
            return true;
        } catch (Exception e) {
            return false;
        } finally {
            if (s != null)
                try {
                    s.close();
                } catch (Exception e) {
                }
        }
    }
}
