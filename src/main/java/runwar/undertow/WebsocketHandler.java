package runwar.undertow;

import static runwar.logging.RunwarLogger.LOG;

import io.undertow.websockets.core.WebSockets;
import io.undertow.io.Sender;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.Headers;
import io.undertow.util.StatusCodes;
import io.undertow.websockets.WebSocketConnectionCallback;
import io.undertow.websockets.core.AbstractReceiveListener;
import io.undertow.websockets.core.BufferedTextMessage;
import io.undertow.websockets.core.WebSocketChannel;
import io.undertow.websockets.spi.WebSocketHttpExchange;
import io.undertow.attribute.ExchangeAttributes;
import io.undertow.server.DefaultResponseListener;
import io.undertow.websockets.core.WebSocketChannel;
import io.undertow.websockets.core.WebSocketVersion;
import io.undertow.websockets.spi.WebSocketHttpExchange;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.websockets.WebSocketProtocolHandshakeHandler;
import io.undertow.websockets.core.StreamSinkFrameChannel;
import io.undertow.websockets.core.WebSocketChannel;
import io.undertow.websockets.core.WebSocketFrameType;
import io.undertow.server.handlers.PathHandler;
import runwar.logging.RunwarLogger;
import runwar.options.ServerOptions;
import runwar.options.SiteOptions;
import runwar.Server;
import runwar.LaunchUtil;
import java.util.Map;
import java.util.List;
import java.util.HashMap;
import java.util.Set;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashSet;

public class WebsocketHandler extends PathHandler {

    private final HttpHandler next;
    private final ServerOptions serverOptions;
    private final SiteOptions siteOptions;
    private final Set<WebSocketChannel> connections = Collections.synchronizedSet(new HashSet<>());
    private final WebSocketProtocolHandshakeHandler webSocketProtocolHandshakeHandler;

    public WebsocketHandler(final HttpHandler next, ServerOptions serverOptions, SiteOptions siteOptions) {
        super(next);
        this.next = next;
        this.serverOptions = serverOptions;
        this.siteOptions = siteOptions;
        this.webSocketProtocolHandshakeHandler = new WebSocketProtocolHandshakeHandler(
                new WebSocketConnectionCallback() {
                    @Override
                    public void onConnect(WebSocketHttpExchange WSexchange, WebSocketChannel channel) {
                        // Add the new channel to the set of connections
                        connections.add(channel);
                        WebsocketReceiveListener listener = new WebsocketReceiveListener(Server.getCurrentExchange(),
                                next,
                                serverOptions,
                                siteOptions, channel);
                        channel.getReceiveSetter().set(listener);
                        channel.getCloseSetter().set((c) -> {
                            connections.remove(channel);
                            listener.onClose(c);
                        });
                        channel.resumeReceives();
                    }
                }, next);

        // In reality, this can just be `/` and apply to all URLs, but a specific suffix
        // makes it easier to proxy at the web server level
        addPrefixPath(siteOptions.webSocketURI(), webSocketProtocolHandshakeHandler);
    }

    /**
     * Get all connections
     */
    public Set<WebSocketChannel> getConnections() {
        return connections;
    }

    public void sendMessage(WebSocketChannel channel, String message) {
        if (channel == null || !channel.isOpen()) {
            return;
        }
        WebSockets.sendText(message, channel, null);
    }

    public void broadcastMessage(String message) {
        // Iterate over all open connections and send the message
        for (WebSocketChannel channel : connections) {
            sendMessage(channel, message);
        }
    }

}