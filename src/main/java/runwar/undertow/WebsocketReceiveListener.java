package runwar.undertow;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.channels.FileChannel;
import java.util.List;

import org.xnio.conduits.ConduitStreamSinkChannel;
import org.xnio.conduits.StreamSinkConduit;
import org.xnio.channels.Channels;
import org.xnio.channels.ConnectedStreamChannel;
import org.xnio.channels.Configurable;
import org.xnio.channels.StreamSourceChannel;
import org.xnio.conduits.WriteReadyHandler;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channel;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.WritableByteChannel;

import org.xnio.ChannelListener;
import org.xnio.Option;
import org.xnio.OptionMap;
import org.xnio.Pool;
import org.xnio.StreamConnection;
import org.xnio.XnioIoThread;
import org.xnio.XnioWorker;
import org.xnio.channels.Configurable;
import org.xnio.channels.ConnectedChannel;
import org.xnio.channels.StreamSinkChannel;
import org.xnio.channels.StreamSourceChannel;
import org.xnio.conduits.ConduitStreamSinkChannel;
import org.xnio.conduits.ConduitStreamSourceChannel;
import org.xnio.conduits.ReadReadyHandler;
import org.xnio.conduits.StreamSinkConduit;
import org.xnio.conduits.StreamSourceConduit;
import org.xnio.conduits.WriteReadyHandler;

import io.undertow.UndertowMessages;
import io.undertow.connector.ByteBufferPool;
import io.undertow.server.Connectors;
import io.undertow.server.DefaultByteBufferPool;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.HttpUpgradeListener;
import io.undertow.server.SSLSessionInfo;
import io.undertow.server.ServerConnection;
import io.undertow.server.XnioBufferPoolAdaptor;
import io.undertow.server.protocol.framed.AbstractFramedChannel;
import io.undertow.util.AttachmentKey;
import io.undertow.util.BadRequestException;
import io.undertow.util.ParameterLimitException;
import io.undertow.websockets.core.AbstractReceiveListener;
import io.undertow.websockets.core.BufferedTextMessage;
import io.undertow.websockets.core.WebSocketChannel;
import runwar.Server;
import runwar.Server.ServerState;
import runwar.options.ServerOptions;
import runwar.options.SiteOptions;
import io.undertow.websockets.core.WebSocketChannel;
import io.undertow.websockets.core.WebSocketFrameType;
import io.undertow.websockets.core.StreamSinkFrameChannel;

@SuppressWarnings("deprecation")
public class WebsocketReceiveListener extends AbstractReceiveListener {
    public static final AttachmentKey<List<Object>> WEBSOCKET_REQUEST_DETAILS = AttachmentKey.create(List.class);

    private HttpServerExchange exchange;
    private HttpHandler next;
    private ServerOptions serverOptions;
    private SiteOptions siteOptions;
    private WebSocketChannel channel;

    /**
     * constructor
     * 
     * @param exchange the HttpServerExchange
     */
    public WebsocketReceiveListener(HttpServerExchange exchange, HttpHandler next, ServerOptions serverOptions,
            SiteOptions siteOptions, WebSocketChannel channel) {
        this.exchange = exchange;
        this.next = next;
        this.serverOptions = serverOptions;
        this.siteOptions = siteOptions;
        this.channel = channel;

        dispatchRequest("onConnect", List.of(channel));
    }

    /**
     * onClose method
     * 
     * @param channel the WebSocketChannel
     */
    public void onClose(AbstractFramedChannel channel) {
        // System.out.println("dispatching onClose");
        dispatchRequest("onClose", List.of(channel));
    }

    /**
     * onFullTextMessage method
     * 
     * @param channel the WebSocketChannel
     * @param message the BufferedTextMessage
     * 
     * @throws IOException
     */
    @Override
    protected void onFullTextMessage(WebSocketChannel channel, BufferedTextMessage message)
            throws IOException {
        // System.out.println("dispatching onFullTextMessage");
        dispatchRequest("onFullTextMessage", List.of(message, channel));
    }

    public void dispatchRequest(String method, List<Object> requestDetails) {
        // If the server is shutting down, there's nothign to do.
        if (Server.getServerState().equals(Server.ServerState.STOPPING)
                || Server.getServerState().equals(Server.ServerState.STOPPED)) {
            return;
        }

        String newUri = siteOptions.webSocketListener() + "?method=onProcess&WSMethod=" + method;
        // System.out.println( "dispatching request: " + newUri );

        final DefaultByteBufferPool bufferPool = new DefaultByteBufferPool(false, 1024, 0, 0);
        MockServerConnection connection = new MockServerConnection(bufferPool);

        // Create a new HttpServerExchange for the new request
        HttpServerExchange newExchange = new HttpServerExchange(connection);
        newExchange.putAttachment(SiteDeploymentManager.SITE_DEPLOYMENT_KEY,
                exchange.getAttachment(SiteDeploymentManager.SITE_DEPLOYMENT_KEY));

        // Put the details on the new exchange so we can access them in our CF code
        newExchange.putAttachment(WEBSOCKET_REQUEST_DETAILS, requestDetails);

        // copy headers (like cookies) any from the original request (except Upgrade)
        this.exchange.getRequestHeaders().forEach(header -> {
            if (!header.getHeaderName().toString().equalsIgnoreCase("Upgrade")) {
                newExchange.getRequestHeaders().add(header.getHeaderName(), header.getFirst());
            }
        });
        newExchange.setRequestMethod(this.exchange.getRequestMethod());
        newExchange.setProtocol(this.exchange.getProtocol());
        newExchange.setRequestScheme(this.exchange.getRequestScheme());
        newExchange.setSourceAddress(this.exchange.getSourceAddress());
        newExchange.setDestinationAddress(this.exchange.getDestinationAddress());

        final StringBuilder sb = new StringBuilder();
        try {
            Connectors.setExchangeRequestPath(newExchange, newUri, sb);
        } catch (ParameterLimitException e) {
            e.printStackTrace();
        }

        // This sets the requestpath, relativepath, querystring, and parses the query
        // parameters
        newExchange.setRequestURI(this.exchange.getRequestScheme() + "://" + this.exchange.getHostAndPort() + newUri,
                true);

        // Call the handler for the new URI
        try {
            HttpHandler exchangeSetter = new HttpHandler() {

                @Override
                public void handleRequest(final HttpServerExchange exchange) throws Exception {
                    HttpServerExchange currentExchange = Server.getCurrentExchange();
                    String currentDeployKey = Server.getCurrentDeploymentKey();
                    try {
                        // This allows the exchange to be available to the thread.
                        Server.setCurrentExchange(newExchange);
                        Server.setCurrentDeploymentKey(currentDeployKey);
                        next.handleRequest(newExchange);
                    } finally {
                        // Clean up after
                        Server.setCurrentExchange(currentExchange);
                        Server.setCurrentDeploymentKey(currentDeployKey);
                    }
                }

                @Override
                public String toString() {
                    return "Websocket Exchange Setter Handler";
                }
            };
            if (exchange.isInIoThread()) {
                exchange.dispatch(exchangeSetter);
            } else {
                exchangeSetter.handleRequest(exchange);
            }
        } catch (Exception e) {
            System.out.println("Error dispatching request: " + e.getMessage());
            e.printStackTrace();
        }

    }

    @SuppressWarnings("deprecation")
    private static class MockServerConnection extends ServerConnection {

        private final ByteBufferPool bufferPool;
        private SSLSessionInfo sslSessionInfo;
        private XnioBufferPoolAdaptor poolAdaptor;

        private MockServerConnection(ByteBufferPool bufferPool) {
            this.bufferPool = bufferPool;
        }

        @Override
        @SuppressWarnings("deprecation")
        public Pool<ByteBuffer> getBufferPool() {
            if (poolAdaptor == null) {
                poolAdaptor = new XnioBufferPoolAdaptor(getByteBufferPool());
            }
            return poolAdaptor;
        }

        @Override
        public ByteBufferPool getByteBufferPool() {
            return bufferPool;
        }

        @Override
        public XnioWorker getWorker() {
            return null;
        }

        @Override
        public XnioIoThread getIoThread() {
            return null;
        }

        @Override
        public HttpServerExchange sendOutOfBandResponse(HttpServerExchange exchange) {
            throw UndertowMessages.MESSAGES.outOfBandResponseNotSupported();
        }

        @Override
        public boolean isContinueResponseSupported() {
            return false;
        }

        @Override
        public void terminateRequestChannel(HttpServerExchange exchange) {

        }

        @Override
        public boolean isOpen() {
            return true;
        }

        @Override
        public boolean supportsOption(Option<?> option) {
            return false;
        }

        @Override
        public <T> T getOption(Option<T> option) throws IOException {
            return null;
        }

        @Override
        public <T> T setOption(Option<T> option, T value) throws IllegalArgumentException, IOException {
            return null;
        }

        @Override
        public void close() throws IOException {
        }

        @Override
        public SocketAddress getPeerAddress() {
            return null;
        }

        @Override
        public <A extends SocketAddress> A getPeerAddress(Class<A> type) {
            return null;
        }

        @Override
        public ChannelListener.Setter<? extends ConnectedChannel> getCloseSetter() {
            return null;
        }

        @Override
        public SocketAddress getLocalAddress() {
            return null;
        }

        @Override
        public <A extends SocketAddress> A getLocalAddress(Class<A> type) {
            return null;
        }

        @Override
        public OptionMap getUndertowOptions() {
            return OptionMap.EMPTY;
        }

        @Override
        public int getBufferSize() {
            return 1024;
        }

        @Override
        public SSLSessionInfo getSslSessionInfo() {
            return sslSessionInfo;
        }

        @Override
        public void setSslSessionInfo(SSLSessionInfo sessionInfo) {
            sslSessionInfo = sessionInfo;
        }

        @Override
        public void addCloseListener(CloseListener listener) {
        }

        @Override
        public StreamConnection upgradeChannel() {
            return null;
        }

        @Override
        public ConduitStreamSinkChannel getSinkChannel() {
            return new ConduitStreamSinkChannel(Configurable.EMPTY, new DummyStreamSinkConduit());
        }

        @Override
        public ConduitStreamSourceChannel getSourceChannel() {
            return new ConduitStreamSourceChannel(Configurable.EMPTY, new DummyStreamSourceConduit());
        }

        @Override
        protected StreamSinkConduit getSinkConduit(HttpServerExchange exchange, StreamSinkConduit conduit) {
            return conduit;
        }

        @Override
        protected boolean isUpgradeSupported() {
            return false;
        }

        @Override
        protected boolean isConnectSupported() {
            return false;
        }

        @Override
        protected void exchangeComplete(HttpServerExchange exchange) {
        }

        @Override
        protected void setUpgradeListener(HttpUpgradeListener upgradeListener) {
            // ignore
        }

        @Override
        protected void setConnectListener(HttpUpgradeListener connectListener) {
            // ignore
        }

        @Override
        protected void maxEntitySizeUpdated(HttpServerExchange exchange) {
        }

        @Override
        public String getTransportProtocol() {
            return "mock";
        }

        @Override
        public boolean isRequestTrailerFieldsSupported() {
            return false;
        }
    }

    private static class DummyStreamSinkConduit implements StreamSinkConduit {

        @Override
        public int write(ByteBuffer src) throws IOException {
            // Ignore all input
            int len = src.remaining();
            src.position(src.limit());
            return len;
        }

        @Override
        public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
            // Ignore all input
            long total = 0;
            for (int i = offset; i < offset + length; i++) {
                total += srcs[i].remaining();
                srcs[i].position(srcs[i].limit());
            }
            return total;
        }

        @Override
        public long writeFinal(ByteBuffer[] srcs, int offset, int length) throws IOException {
            // Ignore all input
            long total = 0;
            for (int i = offset; i < offset + length; i++) {
                total += srcs[i].remaining();
                srcs[i].position(srcs[i].limit());
            }
            return total;
        }

        @Override
        public long transferFrom(StreamSourceChannel source, long count, ByteBuffer throughBuffer) throws IOException {
            // Ignore all input
            return count;
        }

        @Override
        public int writeFinal(ByteBuffer src) throws IOException {
            // Ignore all input
            int len = src.remaining();
            src.position(src.limit());
            return len;
        }

        @Override
        public XnioIoThread getWriteThread() {
            // Return a dummy value or null
            return null;
        }

        @Override
        public XnioWorker getWorker() {
            // Return a dummy value or null
            return null;
        }

        @Override
        public long transferFrom(java.nio.channels.FileChannel src, long position, long count) throws IOException {
            // Ignore all input
            return count;
        }

        @Override
        public void setWriteReadyHandler(WriteReadyHandler handler) {
            // Do nothing
        }

        @Override
        public boolean flush() throws IOException {
            // Do nothing
            return true;
        }

        @Override
        public void terminateWrites() throws IOException {
            // Do nothing
        }

        @Override
        public void truncateWrites() throws IOException {
            // Do nothing
        }

        @Override
        public boolean isWriteShutdown() {
            return false;
        }

        @Override
        public void resumeWrites() {
            // Do nothing
        }

        @Override
        public void suspendWrites() {
            // Do nothing
        }

        @Override
        public void wakeupWrites() {
            // Do nothing
        }

        @Override
        public boolean isWriteResumed() {
            return false;
        }

        @Override
        public void awaitWritable() throws IOException {
            // Do nothing
        }

        @Override
        public void awaitWritable(long time, java.util.concurrent.TimeUnit timeUnit) throws IOException {
            // Do nothing
        }

    }

    private static class DummyStreamSourceConduit implements StreamSourceConduit {

        @Override
        public long transferTo(long position, long count, FileChannel target) throws IOException {
            // Mock implementation: return 0 to indicate no bytes transferred
            return 0;
        }

        @Override
        public long transferTo(long count, ByteBuffer throughBuffer, StreamSinkChannel target) throws IOException {
            // Mock implementation: return 0 to indicate no bytes transferred
            return -1;
        }

        @Override
        public int read(ByteBuffer dst) throws IOException {
            // Mock implementation: return -1 to indicate end of input
            return -1;
        }

        @Override
        public long read(ByteBuffer[] dsts, int offs, int len) throws IOException {
            // Mock implementation: return -1 to indicate end of input
            return -1;
        }

        @Override
        public void terminateReads() throws IOException {
            // Mock implementation: do nothing
        }

        @Override
        public boolean isReadShutdown() {
            // Mock implementation: return true to indicate reads are shutdown
            return true;
        }

        @Override
        public void resumeReads() {
            // Mock implementation: do nothing
        }

        @Override
        public void suspendReads() {
            // Mock implementation: do nothing
        }

        @Override
        public void wakeupReads() {
            // Mock implementation: do nothing
        }

        @Override
        public boolean isReadResumed() {
            // Mock implementation: return false to indicate reads are not resumed
            return false;
        }

        @Override
        public void awaitReadable() throws IOException {
            // Mock implementation: do nothing
        }

        @Override
        public void awaitReadable(long time, java.util.concurrent.TimeUnit timeUnit) throws IOException {
            // Mock implementation: do nothing
        }

        @Override
        public XnioIoThread getReadThread() {
            return null;
        }

        @Override
        public void setReadReadyHandler(ReadReadyHandler handler) {

        }

        @Override
        public XnioWorker getWorker() {
            return null;
        }
    }
}