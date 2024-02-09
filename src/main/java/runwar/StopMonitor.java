package runwar;

import static runwar.logging.RunwarLogger.LOG;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

import runwar.options.ServerOptions;

public class StopMonitor extends Thread {

    private char[] stoppassword;
    private volatile boolean listening = false;
    private volatile boolean systemExitOnStop = true;
    private ServerSocket serverSocket;
    private ServerOptions serverOptions;
    private Server server;

    public StopMonitor(char[] stoppassword, ServerOptions serverOptions) {
        this.stoppassword = stoppassword;
        this.serverOptions = serverOptions;
        this.server = server;
        setDaemon(true);
        setName("StopMonitor");
    }

    @Override
    public void run() {
        // Executor exe = Executors.newCachedThreadPool();
        int exitCode = 0;
        serverSocket = null;
        try {
            serverSocket = new ServerSocket(serverOptions.stopPort(), 1, Server.getInetAddress("127.0.0.1"));
            listening = true;
            LOG.info("Starting 'stop' listener thread - Host: 127.0.0.1 - Socket: " + serverOptions.stopPort());
            while (listening) {
                if (Server.getServerState() == Server.ServerState.STOPPED
                        || Server.getServerState() == Server.ServerState.STOPPING) {
                    listening = false;
                }
                final Socket clientSocket = serverSocket.accept();
                int r, i = 0;
                BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                try {
                    boolean receivedInput = false;
                    while (listening && (r = reader.read()) != -1) {
                        char ch = (char) r;
                        receivedInput = true;
                        if (stoppassword.length > i && ch == stoppassword[i]) {
                            i++;
                        } else {
                            i = 0; // prevent prefix only matches
                        }
                    }
                    if (i == stoppassword.length) {
                        listening = false;
                    } else {
                        if (listening) {
                            // Ignore connections that simplky disconnect without sending any data. This is
                            // probablky just a check to see if the serverr is online
                            if (receivedInput) {
                                LOG.warn("Incorrect password used when trying to stop server.");
                            }
                        } else {
                            LOG.debug("Stopped listening for stop password.");
                        }

                    }
                } catch (java.net.SocketException e) {
                    // reset
                }
                try {
                    clientSocket.close();
                } catch (IOException e) {
                    LOG.error(e);
                }
            }
        } catch (Exception e) {
            LOG.error(e);
            exitCode = 1;
            e.printStackTrace();
        } finally {
            LOG.trace("Closing stop socket");
            try {
                serverSocket.close();
                serverSocket = null;
            } catch (IOException e) {
                LOG.error(e);
                e.printStackTrace();
            }
            try {
                Thread mainThread = Server.getMainThread();
                if (mainThread.isAlive()) {
                    LOG.debug("monitor joining main thread");
                    mainThread.interrupt();
                    try {
                        mainThread.join();
                    } catch (InterruptedException ie) {
                        // expected
                    }
                }
            } catch (Exception e) {
                LOG.error(e);
                e.printStackTrace();
            }
        }
        if (systemExitOnStop) {
            System.exit(exitCode); // this will call our shutdown hook
        }
        return;
    }

    public void stopListening(boolean systemExitOnStop) {
        this.systemExitOnStop = systemExitOnStop;
        listening = false;
        // send a char to the reader so it will stop waiting
        Socket s;
        try {
            s = new Socket(Server.getInetAddress("127.0.0.1"), serverOptions.stopPort());
            OutputStream out = s.getOutputStream();
            out.write('s');
            out.flush();
            out.close();
            s.close();
        } catch (IOException e) {
            // expected if already stopping
        }

    }

}
