package runwar.logging;

import runwar.options.ServerOptions;
import runwar.options.ServerOptionsImpl;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.Filter;
import org.apache.logging.log4j.core.appender.ConsoleAppender;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.apache.logging.log4j.core.appender.RollingFileAppender;
import org.apache.logging.log4j.core.config.NullConfiguration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.filter.ThresholdFilter;
import org.apache.logging.log4j.core.appender.rolling.SizeBasedTriggeringPolicy;
import org.apache.logging.log4j.core.appender.rolling.DefaultRolloverStrategy;

public class LoggerFactory { 

    private static volatile boolean initialized = false;
    private static volatile String logFile;
    private static volatile String logLevel;
    private static volatile List<Appender> appenders;
    private static volatile List<LoggerConfig> loggers;
    private static volatile List<LoggerConfig> urlrewriteLoggers;
    private static volatile RollingFileAppender rewriteLogAppender;
    private static volatile ConsoleAppender consoleAppender;
    private static ServerOptions serverOptions;

    public static synchronized void configure(ServerOptions options) {
        
    	LoggerContext loggerContext = ((LoggerContext)LogManager.getContext(false));
    	loggerContext.setConfiguration(new NullConfiguration());
    	loggerContext.updateLoggers();
    	Configuration log4jConfig = loggerContext.getConfiguration();
    	
        serverOptions = options;
        logLevel = serverOptions.logLevel().toUpperCase();
        appenders = new ArrayList<>();
        loggers = new ArrayList<>();
        Level level = Level.toLevel(logLevel);
        consoleAppender = consoleAppender(serverOptions.getLogPattern());
        appenders.add(consoleAppender);
        LoggerConfig rootLoggerConfig = log4jConfig.getLoggerConfig(LogManager.ROOT_LOGGER_NAME);
        // For some reason the null configuration above doesn't remove the default console appender in the root logger.
        rootLoggerConfig.getAppenders().forEach( (appenderName,appender) -> rootLoggerConfig.removeAppender(appenderName) );
        rootLoggerConfig.setLevel(Level.WARN);
        rootLoggerConfig.addAppender(consoleAppender,level,null);
        

        LoggerConfig DORKBOX_LOG = new LoggerConfig( "dorkbox.systemTray.SystemTray", Level.ERROR, false );
        loggers.add(DORKBOX_LOG);

        LoggerConfig OSCACHE_LOG = new LoggerConfig( "com.opensymphony.oscache.base.Config", Level.WARN, false );
        loggers.add(OSCACHE_LOG);

        LoggerConfig JBOSS_LOG = new LoggerConfig( "org.jboss.logging", Level.WARN, false );
        loggers.add(JBOSS_LOG);

        LoggerConfig UNDERTOW_LOG = new LoggerConfig( "io.undertow.servlet", Level.WARN, false );
        loggers.add(UNDERTOW_LOG);

        LoggerConfig UNDERTOW_PREDICATE_LOG = new LoggerConfig( "io.undertow.predicate", Level.WARN, false );
        loggers.add(UNDERTOW_PREDICATE_LOG);

        LoggerConfig UNDERTOW_PROXY_LOG = new LoggerConfig( "io.undertow.proxy", Level.WARN, false );
        loggers.add(UNDERTOW_PROXY_LOG);        

        LoggerConfig UNDERTOW_REQUEST_DUMPER_LOG = new LoggerConfig( "io.undertow.request.dump", Level.INFO, false );
        loggers.add(UNDERTOW_REQUEST_DUMPER_LOG);

        LoggerConfig UNDERTOW_REQUEST_SECURITY = new LoggerConfig( "io.undertow.request.security", Level.WARN, false );
        loggers.add(UNDERTOW_REQUEST_SECURITY);

        LoggerConfig UNDERTOW_IO_LOG = new LoggerConfig( "io.undertow", Level.WARN, false );
        loggers.add(UNDERTOW_IO_LOG);

        LoggerConfig XNIO_LOG = new LoggerConfig( "org.xnio", Level.WARN, false );
        loggers.add(XNIO_LOG);

        LoggerConfig HTTP_CLIENT_LOG = new LoggerConfig( "org.apache.http.client.protocol", Level.WARN, false );
        loggers.add(HTTP_CLIENT_LOG);

        LoggerConfig RUNWAR_SERVER = new LoggerConfig( "runwar.server", level, false );
        loggers.add(RUNWAR_SERVER);

        LoggerConfig RUNWAR_CONTEXT = new LoggerConfig( "runwar.context", level, false );
        loggers.add(RUNWAR_CONTEXT);

        LoggerConfig RUNWAR_CONFIG = new LoggerConfig( "runwar.config", Level.INFO, false );
        loggers.add(RUNWAR_CONFIG);

        LoggerConfig RUNWAR_SECURITY = new LoggerConfig( "runwar.security", Level.WARN, false );
        loggers.add(RUNWAR_SECURITY);

        LoggerConfig RUNWAR_REQUEST = new LoggerConfig( "runwar.request", Level.WARN, false );
        loggers.add(RUNWAR_REQUEST);

        LoggerConfig RUNWAR_BACKGROUND = new LoggerConfig( "runwar.background", Level.WARN, false );
        RUNWAR_BACKGROUND.setLevel(Level.TRACE);
        RUNWAR_BACKGROUND.addAppender(consoleAppender("%m%n"),RUNWAR_BACKGROUND.getLevel(), null);
        RUNWAR_BACKGROUND.setAdditive(false);

        System.setProperty("org.eclipse.jetty.LEVEL", "WARN");

        if (serverOptions.debug() || !logLevel.equalsIgnoreCase("info")) {

            if( serverOptions.resourceManagerLogging() ) {
                RUNWAR_REQUEST.setLevel(level);	
            }
        	
            if (logLevel.equalsIgnoreCase("trace")) {
                DORKBOX_LOG.setLevel(level);
                appenders.forEach(a -> DORKBOX_LOG.addAppender(a, DORKBOX_LOG.getLevel(), null));
                UNDERTOW_LOG.setLevel(level);
                UNDERTOW_PREDICATE_LOG.setLevel(level);
                UNDERTOW_PROXY_LOG.setLevel(level);
                UNDERTOW_IO_LOG.setLevel(level);                
                HTTP_CLIENT_LOG.setLevel(level);
                RUNWAR_CONFIG.setLevel(level);
                RUNWAR_SERVER.setLevel(level);
                RUNWAR_CONTEXT.setLevel(level);
                RUNWAR_SECURITY.setLevel(level);
                
                rootLoggerConfig.setLevel(level);
                configureUrlRewriteLoggers(true,log4jConfig);
            } else {                
                RUNWAR_SECURITY.setLevel(Level.DEBUG);
                UNDERTOW_PREDICATE_LOG.setLevel(Level.DEBUG);
                UNDERTOW_PROXY_LOG.setLevel(Level.DEBUG);                
                configureUrlRewriteLoggers(false,log4jConfig);
            }
        }

        if (serverOptions.hasLogDir()) {
            logFile = serverOptions.logDir().getPath() + '/' + serverOptions.logFileName() + ".out.txt";
            
            RollingFileAppender fa = RollingFileAppender.newBuilder()
	    		.setName("FileLogger")
	    		.withFileName(logFile)
	            .withFilePattern( logFile + "%i")
	    		.setLayout(
	    				PatternLayout.newBuilder()
	    					.withPattern(serverOptions.getLogPattern())
	    					.build() )
	    		.setFilter(ThresholdFilter.createFilter(Level.toLevel(logLevel), Filter.Result.ACCEPT, Filter.Result.DENY))
	    		.withAppend(true)
	    		.withPolicy(SizeBasedTriggeringPolicy.createPolicy("10MB"))
	    		.withStrategy(
	    				DefaultRolloverStrategy.newBuilder()
	    				.withMax("10")
	    				.build())
	    		.build();
            
            fa.start();
            appenders.add(fa);
            rootLoggerConfig.addAppender(fa,Level.toLevel(logLevel),null);
        }

        loggers.forEach(logger -> {
        	appenders.forEach(appender -> logger.addAppender(appender,logger.getLevel(),null) );
            log4jConfig.addLogger(logger.getName(), logger);
    	});

        loggerContext.updateLoggers();
        initialized = true;

        if (System.getProperty("runwar.dumploggerstyles") != null && Boolean.parseBoolean(System.getProperty("runwar.dumploggerstyles"))) {
            RunwarLogger.LOG.trace("This is a TRACE message");
            RunwarLogger.LOG.debug("This is a DEBUG message");
            RunwarLogger.LOG.warn("This is a WARN message");
            RunwarLogger.LOG.error("This is an ERROR message");
        }
        if (System.getProperty("runwar.listloggers") != null && Boolean.parseBoolean(System.getProperty("runwar.listloggers"))) {
            listLoggers();
        }
    }

    private static ConsoleAppender consoleAppender(String pattern) {
    	
    	ConsoleAppender appender = ConsoleAppender.newBuilder()
			.setName("rw.console")
			.setLayout(
					PatternLayout.newBuilder()
						.withPattern(pattern)
						.build() )
			.setFilter(ThresholdFilter.createFilter(Level.toLevel(logLevel), Filter.Result.ACCEPT, Filter.Result.DENY))
			.build();
    	
    	appender.start();
    	
        return appender;
    }

    public static boolean isInitialized() {
        return initialized;
    }

    public static synchronized boolean initialize() {
    	return true;
        //return initialize(false);
    }

    public static synchronized boolean initialize(boolean force) {
    	return true;
        //    if (!initialized || force)
//            configure(new ServerOptionsImpl().logDir(""));
  // 	      return initialized;
    }

    public static void configureUrlRewriteLoggers(boolean isTrace, Configuration log4jConfig) {
        LoggerConfig REWRITE_CONDITION_LOG = new LoggerConfig( "org.tuckey.web.filters.urlrewrite.Condition", Level.WARN, false );
        LoggerConfig REWRITE_RULE_LOG = new LoggerConfig( "org.tuckey.web.filters.urlrewrite.RuleBase", Level.WARN, false );
        LoggerConfig REWRITE_SUBSTITUTION_LOG = new LoggerConfig( "org.tuckey.web.filters.urlrewrite.substitution.VariableReplacer", Level.WARN, false );
        LoggerConfig REWRITE_EXECUTION_LOG = new LoggerConfig( "org.tuckey.web.filters.urlrewrite.RuleExecutionOutput", Level.WARN, false );
        LoggerConfig REWRITE_WRITER_LOG = new LoggerConfig( "org.tuckey.web.filters.urlrewrite.UrlRewriter", Level.WARN, false );
        LoggerConfig REWRITE_URL_LOG = new LoggerConfig( "org.tuckey.web.filters.urlrewrite", Level.WARN, false );
        LoggerConfig REWRITE_FILTER = new LoggerConfig( "runwar.util.UrlRewriteFilter", Level.WARN, false );
        LoggerConfig REWRITE_LOG = new LoggerConfig( "org.tuckey.web.filters.urlrewrite.utils.Log", Level.WARN, false );
        urlrewriteLoggers = new ArrayList<>();
        urlrewriteLoggers.add(REWRITE_CONDITION_LOG);
        urlrewriteLoggers.add(REWRITE_RULE_LOG);
        urlrewriteLoggers.add(REWRITE_SUBSTITUTION_LOG);
        urlrewriteLoggers.add(REWRITE_EXECUTION_LOG);
        urlrewriteLoggers.add(REWRITE_WRITER_LOG);
        urlrewriteLoggers.add(REWRITE_URL_LOG);
        urlrewriteLoggers.add(REWRITE_FILTER);
        urlrewriteLoggers.add(REWRITE_LOG);

        urlrewriteLoggers.forEach(logger -> {
            log4jConfig.addLogger(logger.getName(), logger);
    	});

        if (isTrace) {
            RunwarLogger.CONF_LOG.infof("Enabling URL rewrite log level: %s", "TRACE");
            urlrewriteLoggers.forEach(logger -> {
                logger.setLevel(Level.TRACE);
                logger.addAppender(consoleAppender(serverOptions.getLogPattern()),logger.getLevel(),null);
            });
        } else {
            RunwarLogger.CONF_LOG.infof("Enabling URL rewrite log level: %s", "DEBUG");
            REWRITE_EXECUTION_LOG.setLevel(Level.DEBUG);
            REWRITE_WRITER_LOG.setLevel(Level.DEBUG);
            urlrewriteLoggers.forEach(logger -> {
                logger.addAppender(consoleAppender(serverOptions.getLogPattern()),logger.getLevel(),null);
            });
        }
        
        if (serverOptions.urlRewriteLog() != null) {
            rewriteLogAppender = RollingFileAppender.newBuilder()
            		.setName("URLRewriteFileLogger")
            		.withFileName(serverOptions.urlRewriteLog().getAbsolutePath())
    	            .withFilePattern( serverOptions.urlRewriteLog().getAbsolutePath() + "%i")
            		.setLayout(
            				PatternLayout.newBuilder()
            					.withPattern(serverOptions.getLogPattern())
            					.build() )
            		.setFilter(ThresholdFilter.createFilter(Level.toLevel(logLevel), Filter.Result.ACCEPT, Filter.Result.DENY))
            		.withAppend(true)
            		.withPolicy(SizeBasedTriggeringPolicy.createPolicy("10MB"))
            		.withStrategy(
            				DefaultRolloverStrategy.newBuilder()
            				.withMax("3")
            				.build())
            		.build();

            rewriteLogAppender.start();
            
            RunwarLogger.CONF_LOG.infof("Enabling URL rewrite log: %s", rewriteLogAppender.getFileName());
            urlrewriteLoggers.forEach(logger -> {
                logger.addAppender(rewriteLogAppender,logger.getLevel(),null);
            });
        }
        
    }

    public static void listLoggers() {

    	LoggerContext loggerContext = ((LoggerContext)LogManager.getContext(false));
    	Configuration log4jConfig = loggerContext.getConfiguration();
        System.out.println("Printing out " + log4jConfig.getLoggers().size() + " loggers.");
        
        log4jConfig.getLoggers().forEach( (loggerName,loggerConfig) -> {
            System.out.println("Logger: " + loggerConfig.getName() + " (" + loggerConfig.getLevel().name() + ")");
            loggerConfig.getAppenders().forEach( (appenderName,appender) -> System.out.println("  appender: " + appenderName) );
        } );
        
    }

}
