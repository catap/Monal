//
//  MLStream.m
//  monalxmpp
//
//  Created by Thilo Molitor on 11.04.21.
//  Copyright © 2021 Monal.im. All rights reserved.
//

#import <Network/Network.h>
#import <monalxmpp/MLConstants.h>
#import <monalxmpp/MLStream.h>
#import <monalxmpp/HelperTools.h>
#import <monalxmpp/monalxmpp-Swift.h>

@class MLCrypto;
@class MLInputStream;
@class MLOutputStream;

#define BUFFER_SIZE 4096
#define CONNECTION_ATTEMPT_DELAY_NSEC (NSEC_PER_MSEC * 250)

@interface MLConnectionAttempt : NSObject
@property (nonatomic, strong) NSDictionary* entry;
@property (nonatomic) nw_connection_t connection;
@property (nonatomic, nullable) nw_framer_t framer;
@property (nonatomic, assign) BOOL wasOpenOnce;
@property (nonatomic, assign) BOOL finished;
@property (nonatomic, strong, nullable) NSError* lastError;
@end

@interface MLSharedStreamState : NSObject
@property (atomic, strong) id<NSStreamDelegate> delegate;
@property (atomic, strong) NSRunLoop* runLoop;
@property (atomic) NSRunLoopMode runLoopMode;
@property (atomic, strong) NSError* error;
@property (atomic) nw_connection_t connection;
@property (atomic) BOOL opening;
@property (atomic) BOOL open;
@property (atomic) BOOL hasTLS;
@property (atomic) nw_parameters_configure_protocol_block_t configure_tls_block;
@property (atomic) nw_framer_t _Nullable framer;
@property (atomic) NSCondition* tlsHandshakeCompleteCondition;
@property (atomic, strong) NSDictionary* _Nullable winningConnectionDetails;
@property (atomic, strong) NSArray<NSDictionary*>* connectEntries;
@property (atomic, strong) NSMutableArray<MLConnectionAttempt*>* raceAttempts;
@property (atomic, strong) dispatch_queue_t raceQueue;
@property (atomic, strong) dispatch_source_t _Nullable raceTimer;
@property (atomic, copy) dispatch_block_t _Nullable raceStarter;
@property (atomic) NSUInteger nextConnectEntryToStart;
@property (atomic) NSUInteger finishedRaceAttempts;
@property (atomic) BOOL raceResolved;
@property (atomic, weak) MLInputStream* inputStream;
@property (atomic, weak) MLOutputStream* outputStream;
@end

@interface MLStream()
{
    id<NSStreamDelegate> _delegate;
}
@property (atomic, strong) MLSharedStreamState* shared_state;
@property (atomic) BOOL open_called;
@property (atomic) BOOL closed;
-(instancetype) initWithSharedState:(MLSharedStreamState*) shared;
-(void) generateEvent:(NSStreamEvent) event;
@end

@interface MLInputStream()
{
    NSMutableData* _buf;
    volatile __block BOOL _reading;
    //this semaphore will make sure that at most only one call to nw_connection_receive() or nw_framer_parse_input() is in flight
    //we use it as mutex: be careful to never increase it beyond 1!!
    //(mutexes can not be unlocked in a thread different from the one it got locked in and NSLock internally uses mutext --> both can not be used)
    dispatch_semaphore_t _read_sem;
}
@property (atomic, readonly) void (^incoming_data_handler)(NSData* _Nullable, BOOL, NSError* _Nullable, BOOL);
@end

@interface MLOutputStream()
{
    volatile __block unsigned long _writing;
}
@end

@implementation MLConnectionAttempt
@end

@implementation MLSharedStreamState

-(instancetype) init
{
    self = [super init];
    self.error = nil;
    self.opening = NO;
    self.open = NO;
    self.hasTLS = NO;
    self.framer = nil;
    self.tlsHandshakeCompleteCondition = [NSCondition new];
    self.winningConnectionDetails = nil;
    self.connectEntries = @[];
    self.raceAttempts = [NSMutableArray new];
    self.raceQueue = dispatch_queue_create("im.monal.networking.race", DISPATCH_QUEUE_SERIAL);
    self.raceTimer = nil;
    self.raceStarter = nil;
    self.nextConnectEntryToStart = 0;
    self.finishedRaceAttempts = 0;
    self.raceResolved = NO;
    self.inputStream = nil;
    self.outputStream = nil;
    return self;
}

@end


@implementation MLInputStream

-(instancetype) initWithSharedState:(MLSharedStreamState*) shared
{
    self = [super initWithSharedState:shared];
    _buf = [NSMutableData new];
    _reading = NO;
    //(see the comments added to the declaration of this member var)
    _read_sem = dispatch_semaphore_create(1);       //the first schedule_read call is always allowed
    
    //this handler will be called by the schedule_read method
    //since the framer swallows all data, nw_connection_receive() and the framer cannot race against each other and deliver reordered data
    weakify(self);
    _incoming_data_handler = ^(NSData* _Nullable content, BOOL is_complete, NSError* _Nullable st_error, BOOL polling_active) {
        strongify(self);
        if(self == nil)
            return;
        
        DDLogVerbose(@"Incoming data handler called with is_complete=%@, st_error=%@, content=%@", bool2str(is_complete), st_error, content);
        @synchronized(self.shared_state) {
            self->_reading = NO;
        }
        BOOL generate_bytes_available_event = NO;
        BOOL generate_error_event = NO;
        
        //handle content received
        if(content != NULL)
        {
            if([content length] > 0)
            {
                @synchronized(self->_buf) {
                    [self->_buf appendData:content];
                }
                generate_bytes_available_event = YES;
            }
        }
        
        //handle errors
        if(st_error)
        {
            //ignore enodata and eagain errors
            if([st_error.domain isEqualToString:(__bridge NSString *)kNWErrorDomainPOSIX] && (st_error.code == ENODATA || st_error.code == EAGAIN))
                DDLogWarn(@"Ignoring transient receive error: %@", st_error);
            else
            {
                @synchronized(self.shared_state) {
                    self.shared_state.error = st_error;
                }
                generate_error_event = YES;
            }
        }
        
        //allow new call to schedule_read
        //(see the comments added to the declaration of this member var)
        dispatch_semaphore_signal(self->_read_sem);
        
        //emit events
        if(generate_bytes_available_event)
            [self generateEvent:NSStreamEventHasBytesAvailable];
        if(generate_error_event)
            [self generateEvent:NSStreamEventErrorOccurred];
        //check if we're read-closed and stop our loop if true (this has to be done *after* processing content)
        if(is_complete)
            [self generateEvent:NSStreamEventEndEncountered];
        
        //try to read again
        if(!is_complete && !generate_error_event && !generate_bytes_available_event && polling_active)
            [self schedule_read];
    };
    return self;
}

-(NSInteger) read:(uint8_t*) buffer maxLength:(NSUInteger) len
{
    @synchronized(self.shared_state) {
        if(self.closed || !self.open_called || !self.shared_state.open)
            return -1;
    }
    BOOL was_smaller = NO;
    @synchronized(self->_buf) {
        if(len > [_buf length])
            len = [_buf length];
        [_buf getBytes:buffer length:len];
        if(len < [_buf length])
        {
            NSData* to_append = [_buf subdataWithRange:NSMakeRange(len, [_buf length]-len)];
            [_buf setLength:0];
            [_buf appendData:to_append];
            was_smaller = YES;
        }
        else
        {
            [_buf setLength:0];
            was_smaller = NO;
        }
    }
    //this has to be done outside of our @synchronized block
    if(was_smaller)
        [self generateEvent:NSStreamEventHasBytesAvailable];
    else if(len > 0)        //only do this if we really provided some data to the reader
    {
        //buffered data got retrieved completely --> schedule new read
        [self schedule_read];
    }
    return len;
}

-(BOOL) getBuffer:(uint8_t* _Nullable *) buffer length:(NSUInteger*) len
{
    return NO;      //this method is not available in this implementation
    /*
    @synchronized(_buf) {
        *len = [_buf length];
        *buffer = (uint8_t* _Nullable)[_buf bytes];
        return YES;
    }*/
}

-(BOOL) hasBytesAvailable
{
    @synchronized(_buf) {
        return _buf && [_buf length];
    }
}

-(NSStreamStatus) streamStatus
{
    @synchronized(self.shared_state) {
        if(self.open_called && self.shared_state.open && _reading)
            return NSStreamStatusReading;
    }
    return [super streamStatus];
}

-(void) schedule_read
{
    @synchronized(self.shared_state) {
        if(self.closed || !self.open_called || !self.shared_state.open)
        {
            DDLogVerbose(@"ignoring schedule_read call because connection is closed: %@", self);
            return;
        }
        
        //don't call nw_connection_receive() or nw_framer_parse_input() multiple times in parallel: this will introduce race conditions
        //(see the comments added to the declaration of this member var)
        if(dispatch_semaphore_wait(_read_sem, DISPATCH_TIME_NOW) != 0)
        {
            DDLogWarn(@"Ignoring call to schedule_read, reading already in progress...");
            return;
        }
        _reading = YES;
        
        if(self.shared_state.framer != nil)
        {
            DDLogDebug(@"dispatching async call to nw_framer_parse_input into framer queue");
            nw_framer_async(self.shared_state.framer, ^{
                DDLogDebug(@"now calling nw_framer_parse_input inside framer queue");
                nw_framer_parse_input(self.shared_state.framer, 1, BUFFER_SIZE, nil, ^size_t(uint8_t* buffer, size_t buffer_length, bool is_complete) {
                    DDLogDebug(@"nw_framer_parse_input got callback with is_complete:%@, length=%zu", bool2str(is_complete), (unsigned long)buffer_length);
                    //we don't want to do "polling" here, our next nw_framer_parse_input will be triggered by the nw_framer_set_input_handler block
                    self.incoming_data_handler([NSData dataWithBytes:buffer length:buffer_length], is_complete, nil, NO);
                    return buffer_length;
                });
            });
        }
        else
        {
            DDLogVerbose(@"calling nw_connection_receive");
            nw_connection_receive(self.shared_state.connection, 1, BUFFER_SIZE, ^(dispatch_data_t content, nw_content_context_t context __unused, bool is_complete, nw_error_t receive_error) {
                DDLogVerbose(@"nw_connection_receive got callback with is_complete:%@, receive_error=%@, length=%zu", bool2str(is_complete), receive_error, (unsigned long)((NSData*)content).length);
                NSError* st_error = nil;
                if(receive_error)
                    st_error = (NSError*)CFBridgingRelease(nw_error_copy_cf_error(receive_error));
                //we want to do "polling" here (e.g. start our next blocking nw_connection_receive call if we did not receive new data nor any error)
                self.incoming_data_handler((NSData*)content, is_complete, st_error, YES);
            });
        }
    }
}

-(void) generateEvent:(NSStreamEvent) event
{
    @synchronized(self.shared_state) {
        [super generateEvent:event];
        //in contrast to the normal nw_receive, the framer receive will not block until we receive any data
        //--> don't call schedule_read if a framer is active, the framer will call it itself once it gets signalled that data is available
        if(event == NSStreamEventOpenCompleted && self.open_called && self.shared_state.open && self.shared_state.framer == nil)
        {
            //we are open now --> allow reading (this will block until we receive any data)
            [self schedule_read];
        }
    }
}

@end

@implementation MLOutputStream

-(instancetype) initWithSharedState:(MLSharedStreamState*) shared
{
    self = [super initWithSharedState:shared];
    _writing = 0;
    return self;
}

-(NSInteger) write:(const uint8_t*) buffer maxLength:(NSUInteger) len
{
    @synchronized(self.shared_state) {
        if(self.closed)
            return -1;
    }
    
    NSCondition* condition = [NSCondition new];
    void (^write_completion)(nw_error_t) = ^(nw_error_t  _Nullable error) {
        DDLogVerbose(@"Write completed...");
        
        @synchronized(self) {
            self->_writing--;
        }
        
        [condition lock];
        [condition signal];
        [condition unlock];
        
        if(error)
        {
            NSError* st_error = (NSError*)CFBridgingRelease(nw_error_copy_cf_error(error));
            @synchronized(self.shared_state) {
                self.shared_state.error = st_error;
            }
            [self generateEvent:NSStreamEventErrorOccurred];
        }
        else
        {
            @synchronized(self) {
                if([self hasSpaceAvailable])
                    [self generateEvent:NSStreamEventHasSpaceAvailable];
            }
        }
    };
    
    //the call to dispatch_get_main_queue() is a dummy because we are using DISPATCH_DATA_DESTRUCTOR_DEFAULT which is performed inline
    dispatch_data_t data = dispatch_data_create(buffer, len, dispatch_get_main_queue(), DISPATCH_DATA_DESTRUCTOR_DEFAULT);
    
    //support tcp fast open for all data sent before the connection got opened, but only usable for connections NOT using a framer
    /*if(!self.open_called)
    {
        DDLogInfo(@"Sending TCP fast open early data: %@", data);
        nw_connection_send(self.shared_state.connection, data, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, NO, NW_CONNECTION_SEND_IDEMPOTENT_CONTENT);
        return len;
    }*/
    
    @synchronized(self.shared_state) {
        if(!self.open_called || !self.shared_state.open)
            return -1;
    }
    @synchronized(self) {
        _writing++;
    }
    
    //decide if we should use our framer or normal nw_connection_send()
    //framer being nil is the hot path --> make it fast (we'll check if it's still != nil in an @synchronized block below --> still threadsafe
    //for the record: wrapping this into an @synchronized block would create a deadlock with our condition wait inside this
    //block and the second @synchronized block inside nw_framer_async()
    [condition lock];
    if(self.shared_state.framer != nil)
    {
        DDLogDebug(@"Switching async to framer thread in COLD path...");
        //framer methods must be called inside the framer thread
        nw_framer_async(self.shared_state.framer, ^{
            //make sure that self.shared_state.framer still isn't nil, if it is, we fall back to nw_connection_send()
            @synchronized(self.shared_state) {
                if(self.shared_state.framer != nil)
                {
                    DDLogDebug(@"Calling nw_framer_write_output_data() in COLD path...");
                    nw_framer_write_output_data(self.shared_state.framer, data);
                    //make sure to not call the write_completion inside this @synchronized block
                    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                        write_completion(nil);      //TODO: can we detect write errors like in nw_connection_send() somehow?
                    });
                }
                else
                {
                    //make sure to not call nw_connection_send() and the following write_completion inside this @synchronized block
                    //we don't know if calling nw_connection_send() from the framer thread is safe --> just don't do this to be on the safe side
                    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                        DDLogDebug(@"Calling nw_connection_send() in COLD path...");
                        nw_connection_send(self.shared_state.connection, data, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, NO, write_completion);
                    });
                }
            }
        });
        //wait for write complete signal
        [condition wait];
        [condition unlock];
        DDLogDebug(@"Returning from write in COLD path: %zu", (unsigned long)len);
        return len;     //return instead of else to leave @synchronized block early
    }
    DDLogVerbose(@"Calling nw_connection_send() in hot path...");
    nw_connection_send(self.shared_state.connection, data, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, NO, write_completion);
    //wait for write complete signal
    [condition wait];
    [condition unlock];
    DDLogVerbose(@"Returning from write in hot path: %zu", (unsigned long)len);
    return len;
}

-(BOOL) hasSpaceAvailable
{
    @synchronized(self) {
        return self.open_called && self.shared_state.open && !self.closed && _writing == 0;
    }
}

-(NSStreamStatus) streamStatus
{
    @synchronized(self) {
        if(self.open_called && self.shared_state.open && !self.closed && _writing > 0)
            return NSStreamStatusWriting;
    }
    return [super streamStatus];
}

-(void) generateEvent:(NSStreamEvent) event
{
    @synchronized(self.shared_state) {
        [super generateEvent:event];
        //generate the first NSStreamEventHasSpaceAvailable event directly after our NSStreamEventOpenCompleted event
        //(the network framework buffers outgoing data itself, e.g. it is always writable)
        if(event == NSStreamEventOpenCompleted && [self hasSpaceAvailable])
            [super generateEvent:NSStreamEventHasSpaceAvailable];
    }
}

@end

@implementation MLStream

+(void) connectWithSNIDomain:(NSString*) SNIDomain connectHost:(NSString*) host connectPort:(NSNumber*) port tls:(BOOL) tls inputStream:(NSInputStream* _Nullable * _Nonnull) inputStream  outputStream:(NSOutputStream* _Nullable * _Nonnull) outputStream logtag:(id _Nullable) logtag
{
    NSDictionary* connectEntry = @{
        @"connectHost": host,
        @"connectPort": port,
        @"isSecure": [NSNumber numberWithBool:tls],
    };
    [self connectWithSNIDomain:SNIDomain connectEntries:@[connectEntry] inputStream:inputStream outputStream:outputStream logtag:logtag];
}

+(void) connectWithSNIDomain:(NSString*) SNIDomain connectEntries:(NSArray<NSDictionary*>*) connectEntries inputStream:(NSInputStream* _Nullable * _Nonnull) inputStream  outputStream:(NSOutputStream* _Nullable * _Nonnull) outputStream logtag:(id _Nullable) logtag
{
    MLAssert([connectEntries count] > 0, @"connectEntries must not be empty!");
    
    //create state
    //create and configure public stream instances returned later
    MLSharedStreamState* shared_state = [[MLSharedStreamState alloc] init];
    MLInputStream* input = [[MLInputStream alloc] initWithSharedState:shared_state];
    MLOutputStream* output = [[MLOutputStream alloc] initWithSharedState:shared_state];
    shared_state.inputStream = input;
    shared_state.outputStream = output;
    shared_state.connectEntries = [connectEntries copy];
    
    nw_parameters_configure_protocol_block_t tcp_options = ^(nw_protocol_options_t tcp_options) {
        nw_tcp_options_set_enable_fast_open(tcp_options, YES);
        //nw_tcp_options_set_no_delay(tcp_options, YES);            //disable nagle's algorithm
        //nw_tcp_options_set_connection_timeout(tcp_options, 4);
    };
    nw_parameters_configure_protocol_block_t configure_tls_block = ^(nw_protocol_options_t tls_options) {
        sec_protocol_options_t options = nw_tls_copy_sec_protocol_options(tls_options);
        sec_protocol_options_set_tls_server_name(options, [SNIDomain cStringUsingEncoding:NSUTF8StringEncoding]);
        sec_protocol_options_add_tls_application_protocol(options, "xmpp-client");
        sec_protocol_options_set_tls_ocsp_enabled(options, 1);
        sec_protocol_options_set_tls_false_start_enabled(options, 1);
        sec_protocol_options_set_min_tls_protocol_version(options, tls_protocol_version_TLSv12);
        //sec_protocol_options_set_max_tls_protocol_version(options, tls_protocol_version_TLSv12);
        sec_protocol_options_set_tls_sct_enabled(options, 1);
        sec_protocol_options_set_tls_resumption_enabled(options, 1);
        sec_protocol_options_set_tls_tickets_enabled(options, 1);
        sec_protocol_options_set_tls_renegotiation_enabled(options, 0);
        //tls-exporter channel-binding is only usable for TLSv1.2 if ECDHE is used instead of RSA key exchange
        //(see https://mitls.org/pages/attacks/3SHAKE)
        //see also https://developer.apple.com/documentation/security/preventing_insecure_network_connections?language=objc
        sec_protocol_options_append_tls_ciphersuite_group(options, tls_ciphersuite_group_ats);
    };
    //configure shared state
    shared_state.configure_tls_block = configure_tls_block;
    
    void (^cancelRaceTimer)(void) = ^{
        if(shared_state.raceTimer != nil)
        {
            dispatch_source_cancel(shared_state.raceTimer);
            shared_state.raceTimer = nil;
        }
    };

    void (^finishWithErrorIfNeeded)(void) = ^{
        if(shared_state.raceResolved)
            return;
        if(shared_state.nextConnectEntryToStart < [shared_state.connectEntries count])
            return;
        if([shared_state.raceAttempts count] == 0 || shared_state.finishedRaceAttempts < [shared_state.raceAttempts count])
            return;
        
        NSError* lastError = nil;
        for(MLConnectionAttempt* entry in [shared_state.raceAttempts reverseObjectEnumerator])
            if(entry.lastError != nil)
            {
                lastError = entry.lastError;
                break;
            }
        if(lastError == nil)
            lastError = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCannotConnectToHost userInfo:nil];

        DDLogError(@"%@: All connection attempts failed: %@", logtag, lastError);
        cancelRaceTimer();
        @synchronized(shared_state) {
            shared_state.error = lastError;
            shared_state.open = NO;
            shared_state.framer = nil;
        }
        [input generateEvent:NSStreamEventErrorOccurred];
        [output generateEvent:NSStreamEventErrorOccurred];
    };
    
    __block void (^selectWinner)(MLConnectionAttempt*);
    selectWinner = ^(MLConnectionAttempt* winner) {
        if(shared_state.raceResolved)
            return;
        shared_state.raceResolved = YES;

        NSDictionary* entry = winner.entry;
        NSString* host = nilExtractor(entry[@"connectHost"]);
        if(host == nil)
            host = nilExtractor(entry[@"server"]);
        NSNumber* port = nilExtractor(entry[@"connectPort"]);
        if(port == nil)
            port = nilExtractor(entry[@"port"]);
        BOOL isSecure = [entry[@"isSecure"] boolValue];
        
        DDLogInfo(@"%@: Connection attempt won: host=%@ port=%@ directTLS=%@", logtag, host, port, bool2str(isSecure));
        cancelRaceTimer();
        @synchronized(shared_state) {
            shared_state.connection = winner.connection;
            shared_state.framer = winner.framer;
            shared_state.hasTLS = isSecure;
            shared_state.open = YES;
            shared_state.error = nil;
            shared_state.winningConnectionDetails = @{
                @"connectHost": nilWrapper(host),
                @"connectPort": nilWrapper(port),
                @"isSecure": [NSNumber numberWithBool:isSecure],
            };
        }

        for(MLConnectionAttempt* attempt in shared_state.raceAttempts)
            if(attempt.connection != winner.connection)
                nw_connection_force_cancel(attempt.connection);

        //make sure to not do this inside the framer thread to not cause any deadlocks
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [input generateEvent:NSStreamEventOpenCompleted];
            [output generateEvent:NSStreamEventOpenCompleted];
        });
    };

    void (^markAttemptFinished)(MLConnectionAttempt*, NSError*) = ^(MLConnectionAttempt* attempt, NSError* error) {
        if(error != nil)
            attempt.lastError = error;
        if(attempt.finished)
            return;
        attempt.finished = YES;
        shared_state.finishedRaceAttempts++;
        finishWithErrorIfNeeded();
    };

    __block void (^startAttemptForEntry)(NSDictionary*);
    startAttemptForEntry = ^(NSDictionary* entry) {
        NSString* host = nilExtractor(entry[@"connectHost"]);
        if(host == nil)
            host = nilExtractor(entry[@"server"]);
        NSNumber* port = nilExtractor(entry[@"connectPort"]);
        if(port == nil)
            port = nilExtractor(entry[@"port"]);
        BOOL tls = [entry[@"isSecure"] boolValue];
        
        if(host == nil || port == nil)
        {
            DDLogError(@"%@: Ignoring malformed connect entry: %@", logtag, entry);
            MLConnectionAttempt* attempt = [MLConnectionAttempt new];
            attempt.entry = entry;
            [shared_state.raceAttempts addObject:attempt];
            markAttemptFinished(attempt, [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorBadURL userInfo:nil]);
            return;
        }

        MLConnectionAttempt* attempt = [MLConnectionAttempt new];
        attempt.entry = entry;
        attempt.wasOpenOnce = NO;
        attempt.finished = NO;
        attempt.lastError = nil;
        [shared_state.raceAttempts addObject:attempt];

        //configure tcp connection parameters
        nw_parameters_t parameters;
        if(tls)
            parameters = nw_parameters_create_secure_tcp(configure_tls_block, tcp_options);
        else
        {
            //create simple framer and append it to our stack
            //first framer initialization is allowed to send tcp early data
            parameters = nw_parameters_create_secure_tcp(NW_PARAMETERS_DISABLE_PROTOCOL, tcp_options);
            volatile __block int startupCounter = 0;
            nw_protocol_definition_t starttls_framer_definition = nw_framer_create_definition([[[NSUUID UUID] UUIDString] UTF8String], NW_FRAMER_CREATE_FLAGS_DEFAULT, ^(nw_framer_t framer) {
                //we don't need any locking for our counter because all framers will be started in the same internal network queue
                int framerId = startupCounter++;
                DDLogInfo(@"%@: Framer(%d) %@ start called for %@", logtag, framerId, framer, host);
                nw_framer_set_stop_handler(framer, (nw_framer_stop_handler_t)^(nw_framer_t _Nullable framer) {
                    DDLogInfo(@"%@: Framer(%d) stop called: %@", logtag, framerId, framer);
                    return YES;
                });

                //some weird apple stuff creates the framer twice: once directly when starting the tcp handshake
                //and once a few milliseconds later, presumably after the tcp connection was established successfully
                //--> ignore all but the first one
                if(framerId < 1)
                {
                    //we have to simulate nw_connection_state_ready because the connection state will not reflect that while our framer is active
                    //--> use framer start as "connection active" signal
                    //first framer start is allowed to directly send data which will be used as tcp early data
                    attempt.framer = framer;
                    if(!attempt.wasOpenOnce)
                    {
                        attempt.wasOpenOnce = YES;
                        selectWinner(attempt);
                    }
                    nw_framer_set_input_handler(framer, ^size_t(nw_framer_t framer) {
                        if(shared_state.connection == attempt.connection && shared_state.framer == framer)
                        {
                            DDLogDebug(@"Got new input for winning framer: %@", framer);
                            [input schedule_read];
                        }
                        return 0;
                    });
                    nw_framer_set_output_handler(framer, ^(nw_framer_t framer, nw_framer_message_t message, size_t message_length, bool is_complete) {
                        MLAssert(NO, @"Unexpected outgoing bytes in framer!", (@{
                            @"logtag": nilWrapper(logtag),
                            @"framer": framer,
                            @"message": message,
                            @"message_length": @(message_length),
                            @"is_complete": bool2str(is_complete),
                        }));
                    });
                }
                else
                    DDLogVerbose(@"Ignoring subsequent framer...");

                return nw_framer_start_result_will_mark_ready;
            });
            DDLogInfo(@"%@: Not doing direct TLS for %@:%@: appending framer to protocol stack...", logtag, host, port);
            nw_protocol_stack_prepend_application_protocol(nw_parameters_copy_default_protocol_stack(parameters), nw_framer_create_options(starttls_framer_definition));
        }

        //needed to activate tcp fast open with apple's internal tls framer
        nw_parameters_set_fast_open_enabled(parameters, YES);
        //use dnssec if configured
        if([[HelperTools defaultsDB] boolForKey: @"useDnssecForAllConnections"])
            nw_parameters_set_requires_dnssec_validation(parameters, YES);

        //create and configure connection object
        nw_endpoint_t endpoint = nw_endpoint_create_host([host cStringUsingEncoding:NSUTF8StringEncoding], [[port stringValue] cStringUsingEncoding:NSUTF8StringEncoding]);
        attempt.connection = nw_connection_create(endpoint, parameters);
        nw_connection_set_queue(attempt.connection, shared_state.raceQueue);

        DDLogInfo(@"%@: Starting connection attempt %lu/%lu to %@:%@ directTLS=%@", logtag, (unsigned long)[shared_state.raceAttempts count], (unsigned long)[shared_state.connectEntries count], host, port, bool2str(tls));
        //configure state change handler proxying state changes to our public stream instances
        nw_connection_set_state_changed_handler(attempt.connection, ^(nw_connection_state_t state, nw_error_t error) {
            //connection was opened once (e.g. opening=YES) and closed later on (e.g. open=NO)
            if(shared_state.raceResolved && shared_state.connection != attempt.connection)
            {
                DDLogVerbose(@"%@: Ignoring callback for losing attempt %@:%@ state=%u", logtag, host, port, state);
                return;
            }

            //always handle errors regardless of current state (cert errors etc.)
            NSError* st_error = nil;
            if(error != nil)
            {
                st_error = (NSError*)CFBridgingRelease(nw_error_copy_cf_error(error));
                DDLogVerbose(@"%@: Connection attempt %@:%@ got error in state %u: %@", logtag, host, port, state, st_error);
                attempt.lastError = st_error;
            }

            if(state == nw_connection_state_waiting)
            {
                //do nothing here, documentation says the connection will be automatically retried "when conditions are favourable"
                //which seems to mean: if the network path changed (for example connectivity regained)
                //if this happens inside the connection timeout all is ok
                //if not, the connection will be cancelled already and everything will be ok, too
                DDLogVerbose(@"%@: Connection attempt waiting %@:%@ (%@)", logtag, host, port, error);
            }
            else if(state == nw_connection_state_failed)
            {
                //errors already reported by generic handling above
                DDLogError(@"%@: Connection attempt failed %@:%@ (%@)", logtag, host, port, error);

                //if this is the winning connection, propagate the error to our stream users and unblock any STARTTLS handshake
                BOOL winnerFailed = NO;
                @synchronized(shared_state) {
                    if(shared_state.raceResolved && shared_state.connection == attempt.connection)
                    {
                        winnerFailed = YES;
                        if(st_error != nil)
                            shared_state.error = st_error;
                        else if(attempt.lastError != nil)
                            shared_state.error = attempt.lastError;
                        else
                            shared_state.error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCannotConnectToHost userInfo:nil];
                        shared_state.open = NO;
                        shared_state.framer = nil;
                    }
                }
                if(winnerFailed)
                {
                    [shared_state.tlsHandshakeCompleteCondition lock];
                    [shared_state.tlsHandshakeCompleteCondition signal];
                    [shared_state.tlsHandshakeCompleteCondition unlock];
                    [input generateEvent:NSStreamEventErrorOccurred];
                    [output generateEvent:NSStreamEventErrorOccurred];
                }
                markAttemptFinished(attempt, st_error);
            }
            else if(state == nw_connection_state_ready)
            {
                DDLogInfo(@"%@: Connection attempt ready %@:%@ directTLS=%@ wasOpenOnce=%@", logtag, host, port, bool2str(tls), bool2str(attempt.wasOpenOnce));
                if(!attempt.wasOpenOnce)
                {
                    attempt.wasOpenOnce = YES;
                    selectWinner(attempt);
                }
                else if(!tls && shared_state.connection == attempt.connection)
                {
                    //the nw_connection_state_ready state while already wasOpenOnce comes from our framer set to ready
                    //this informs the upper layer that the connection is in ready state now, but we already treat the framer start
                    //as connection ready event
                    @synchronized(shared_state) {
                        //tls handshake completed now
                        shared_state.hasTLS = YES;
                    }
                    //unlock thread waiting on tls handshake completion (starttls)
                    [shared_state.tlsHandshakeCompleteCondition lock];
                    [shared_state.tlsHandshakeCompleteCondition signal];
                    [shared_state.tlsHandshakeCompleteCondition unlock];
                    //we still want to inform our stream users that they can write data now and schedule a read operation
                    [output generateEvent:NSStreamEventHasSpaceAvailable];
                    [input schedule_read];
                }
            }
            else if(state == nw_connection_state_cancelled)
            {
                //ignore this (we use reference counting)
                DDLogVerbose(@"%@: Connection attempt cancelled %@:%@", logtag, host, port);
                if(!shared_state.raceResolved)
                    markAttemptFinished(attempt, st_error);
            }
            else if(state == nw_connection_state_invalid)
                //ignore all other states (preparing, invalid)
                DDLogVerbose(@"%@: ignoring state invalid %@:%@", logtag, host, port);
            else if(state == nw_connection_state_preparing)
                //ignore all other states (preparing, invalid)
                DDLogVerbose(@"%@: ignoring state preparing %@:%@", logtag, host, port);
            else
                unreachable();
        });

        nw_connection_start(attempt.connection);
    };

    void (^startNextAttempt)(void) = ^{
        if(shared_state.raceResolved)
            return;
        if(shared_state.nextConnectEntryToStart >= [shared_state.connectEntries count])
            return;

        NSDictionary* entry = shared_state.connectEntries[shared_state.nextConnectEntryToStart];
        shared_state.nextConnectEntryToStart++;
        startAttemptForEntry(entry);

        if(shared_state.nextConnectEntryToStart >= [shared_state.connectEntries count])
            cancelRaceTimer();
    };

    weakify(shared_state);
    shared_state.raceStarter = ^{
        strongify(shared_state);
        if(shared_state == nil)
            return;

        dispatch_async(shared_state.raceQueue, ^{
            strongify(shared_state);
            if(shared_state == nil)
                return;

            DDLogInfo(@"%@: Starting happy-eyeballs race with %lu entries", logtag, (unsigned long)[shared_state.connectEntries count]);
            if(shared_state.raceResolved)
                return;
            startNextAttempt();
            if(shared_state.raceResolved)
                return;
            if(shared_state.nextConnectEntryToStart < [shared_state.connectEntries count])
            {
                shared_state.raceTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, shared_state.raceQueue);
                dispatch_source_set_timer(shared_state.raceTimer, dispatch_time(DISPATCH_TIME_NOW, CONNECTION_ATTEMPT_DELAY_NSEC), CONNECTION_ATTEMPT_DELAY_NSEC, NSEC_PER_MSEC * 10);
                dispatch_source_set_event_handler(shared_state.raceTimer, ^{
                    startNextAttempt();
                });
                dispatch_resume(shared_state.raceTimer);
            }
        });
    };
    
    *inputStream = (NSInputStream*)input;
    *outputStream = (NSOutputStream*)output;
}

-(void) startTLS
{
    [self.shared_state.tlsHandshakeCompleteCondition lock];
    @synchronized(self.shared_state) {
        if(self.shared_state.error != nil || !self.shared_state.open)
        {
            [self.shared_state.tlsHandshakeCompleteCondition unlock];
            return;
        }
        MLAssert(!self.shared_state.hasTLS, @"We already have TLS on this connection!");
        MLAssert(self.shared_state.framer != nil, @"Trying to start tls handshake without having a running framer!");
        DDLogInfo(@"Starting TLS handshake on framer: %@", self.shared_state.framer);
        nw_framer_async(self.shared_state.framer, ^{
            @synchronized(self.shared_state) {
                DDLogVerbose(@"Prepending tls to framer: %@", self.shared_state.framer);
                nw_framer_t framer = self.shared_state.framer;
                self.shared_state.framer = nil;
                nw_protocol_options_t tls_options = nw_tls_create_options();
                self.shared_state.configure_tls_block(tls_options);
                nw_framer_prepend_application_protocol(framer, tls_options);
                nw_framer_pass_through_input(framer);
                nw_framer_pass_through_output(framer);
                nw_framer_mark_ready(framer);
                DDLogVerbose(@"Framer deactivated and TLS prepended now...");
            }
        });
    }
    while(YES)
    {
        @synchronized(self.shared_state) {
            if(self.shared_state.hasTLS || self.shared_state.error != nil || !self.shared_state.open)
                break;
        }
        [self.shared_state.tlsHandshakeCompleteCondition wait];
    }
    [self.shared_state.tlsHandshakeCompleteCondition unlock];
    DDLogInfo(@"TLS handshake completed: %@...", bool2str(self.shared_state.hasTLS));
}

-(BOOL) hasTLS
{
    @synchronized(self.shared_state) {
        return self.shared_state.hasTLS;
    }
}

-(instancetype) initWithSharedState:(MLSharedStreamState*) shared
{
    self = [super init];
    self.shared_state = shared;
    @synchronized(self.shared_state) {
        self.open_called = NO;
        self.closed = NO;
        self.delegate = self;
    }
    return self;
}

-(void) generateEvent:(NSStreamEvent) event
{
    @synchronized(self.shared_state) {
        //don't schedule delegate calls if no runloop was specified
        if(self.shared_state.runLoop == nil)
            return;
        //make sure to NOT hold the @synchronized lock when calling the delegate to not introduce deadlocks
        BOOL handleEvent = NO;
        if(event == NSStreamEventOpenCompleted && self.open_called && self.shared_state.open)
            handleEvent = YES;
        else if(event == NSStreamEventHasBytesAvailable && self.open_called && self.shared_state.open)
            handleEvent = YES;
        else if(event == NSStreamEventHasSpaceAvailable && self.open_called && self.shared_state.open)
            handleEvent = YES;
        else if(event == NSStreamEventErrorOccurred)
            handleEvent = YES;
        else if(event == NSStreamEventEndEncountered && self.open_called && self.shared_state.open)
            handleEvent = YES;
        //check if the event should be handled
        if(!handleEvent)
            DDLogVerbose(@"Ignoring event %ld", (long)event);
        else
        {
            //schedule the delegate calls in the runloop that was registered
            CFRunLoopPerformBlock([self.shared_state.runLoop getCFRunLoop], (__bridge CFStringRef)self.shared_state.runLoopMode, ^{
                [self->_delegate stream:self handleEvent:event];
            });
            //trigger wakeup of runloop to execute the block as soon as possible
            CFRunLoopWakeUp([self.shared_state.runLoop getCFRunLoop]);
        }
    }
}

-(void) open
{
    dispatch_block_t raceStarter = nil;
    nw_connection_t connection = nil;
    @synchronized(self.shared_state) {
        MLAssert(!self.closed, @"streams can not be reopened!");
        self.open_called = YES;
        if(!self.shared_state.opening)
        {
            raceStarter = self.shared_state.raceStarter;
            connection = self.shared_state.connection;
            self.shared_state.opening = YES;
        }
        //already opened by stream for other direction? --> directly trigger open event
        if(self.shared_state.open)
            [self generateEvent:NSStreamEventOpenCompleted];
    }
    if(raceStarter != nil)
    {
        DDLogVerbose(@"Calling race starter...");
        raceStarter();
    }
    else if(connection != nil)
    {
        DDLogVerbose(@"Calling nw_connection_start()...");
        nw_connection_start(connection);
    }
}

-(void) close
{
    nw_connection_t connection;
    NSArray<MLConnectionAttempt*>* raceAttempts;
    dispatch_source_t raceTimer;
    @synchronized(self.shared_state) {
        connection = self.shared_state.connection;
        raceAttempts = [self.shared_state.raceAttempts copy];
        raceTimer = self.shared_state.raceTimer;
        self.shared_state.raceTimer = nil;
        self.shared_state.raceStarter = nil;
        self.shared_state.raceResolved = YES;
        self.shared_state.opening = NO;
        self.shared_state.open = NO;
        self.shared_state.framer = nil;
        self.shared_state.connection = nil;
        self.shared_state.winningConnectionDetails = nil;
        self.shared_state.connectEntries = @[];
        self.shared_state.raceAttempts = [NSMutableArray new];
        self.shared_state.nextConnectEntryToStart = 0;
        self.shared_state.finishedRaceAttempts = 0;
    }
    if(raceTimer != nil)
        dispatch_source_cancel(raceTimer);
    for(MLConnectionAttempt* attempt in raceAttempts)
        if(attempt.connection != nil && attempt.connection != connection)
            nw_connection_force_cancel(attempt.connection);

    if(connection == nil)
    {
        @synchronized(self.shared_state) {
            self.closed = YES;
        }
        //unlock thread waiting on tls handshake
        [self.shared_state.tlsHandshakeCompleteCondition lock];
        [self.shared_state.tlsHandshakeCompleteCondition signal];
        [self.shared_state.tlsHandshakeCompleteCondition unlock];
        return;
    }

    DDLogVerbose(@"Closing connection via nw_connection_send()...");
    nw_connection_send(connection, NULL, NW_CONNECTION_FINAL_MESSAGE_CONTEXT, YES, ^(nw_error_t  _Nullable error) {
        if(error)
        {
            NSError* st_error = (NSError*)CFBridgingRelease(nw_error_copy_cf_error(error));
            @synchronized(self.shared_state) {
                self.shared_state.error = st_error;
            }
            [self generateEvent:NSStreamEventErrorOccurred];
            nw_connection_force_cancel(connection);
        }
        else
            nw_connection_cancel(connection);
    });
    @synchronized(self.shared_state) {
        self.closed = YES;
    }

    //unlock thread waiting on tls handshake
    [self.shared_state.tlsHandshakeCompleteCondition lock];
    [self.shared_state.tlsHandshakeCompleteCondition signal];
    [self.shared_state.tlsHandshakeCompleteCondition unlock];
}

-(void) setDelegate:(id<NSStreamDelegate>) delegate
{
    _delegate = delegate;
    if(_delegate == nil)
        _delegate = self;
}

-(void) scheduleInRunLoop:(NSRunLoop*) loop forMode:(NSRunLoopMode) mode
{
    @synchronized(self.shared_state) {
        self.shared_state.runLoop = loop;
        self.shared_state.runLoopMode = mode;
    }
}

-(void) removeFromRunLoop:(NSRunLoop*) loop forMode:(NSRunLoopMode) mode
{
    @synchronized(self.shared_state) {
        self.shared_state.runLoop = nil;
        self.shared_state.runLoopMode = mode;
    }
}

-(id) propertyForKey:(NSStreamPropertyKey) key
{
    return [super propertyForKey:key];
}

-(BOOL) setProperty:(id) property forKey:(NSStreamPropertyKey) key
{
    return [super setProperty:property forKey:key];
}

-(NSStreamStatus) streamStatus
{
    @synchronized(self.shared_state) {
        if(self.shared_state.error)
            return NSStreamStatusError;
        else if(!self.open_called && self.closed)
            return NSStreamStatusNotOpen;
        else if(self.open_called && self.shared_state.open)
            return NSStreamStatusOpen;
        else if(self.open_called)
            return NSStreamStatusOpening;
        else if(self.closed)
            return NSStreamStatusClosed;
    }
    unreachable();
    return 0;
}

-(NSError*) streamError
{
    NSError* error = nil;
    @synchronized(self.shared_state) {
        error = self.shared_state.error;
    }
    return error;
}

-(NSDictionary* _Nullable) winningConnectionDetails
{
    NSDictionary* details = nil;
    @synchronized(self.shared_state) {
        details = self.shared_state.winningConnectionDetails;
    }
    return details;
}

//list supported channel-binding types (highest security first!)
-(NSArray*) supportedChannelBindingTypes
{
    //we made sure we only use PFS based ciphers for which tls-exporter can safely be used even with TLS1.2
    //(see https://mitls.org/pages/attacks/3SHAKE)
    return @[@"tls-exporter", @"tls-server-end-point"];
    
    /*
    //BUT: other implementations simply don't support tls-exporter on non-tls1.3 connections --> do the same for compatibility
    if(self.isTLS13)
        return @[@"tls-exporter", @"tls-server-end-point"];
    return @[@"tls-server-end-point"];
    */
}

-(NSData* _Nullable) channelBindingDataForType:(NSString* _Nullable) type
{
    //don't log a warning in this special case
    if(type == nil)
        return nil;
    
    if([@"tls-exporter" isEqualToString:type])
        return [self channelBindingData_TLSExporter];
    else if([@"tls-server-end-point" isEqualToString:type])
        return [self channelBindingData_TLSServerEndPoint];
    else if([kServerDoesNotFollowXep0440Error isEqualToString:type])
        return [kServerDoesNotFollowXep0440Error dataUsingEncoding:NSUTF8StringEncoding];
    
    unreachable(@"Trying to use unknown channel-binding type!", (@{@"type":type}));
}

-(BOOL) isTLS13
{
    @synchronized(self.shared_state) {
        MLAssert([self streamStatus] >= NSStreamStatusOpen && [self streamStatus] < NSStreamStatusClosed, @"Stream must be open to call this method!", (@{@"streamStatus": @([self streamStatus])}));
        MLAssert(self.shared_state.hasTLS, @"Stream must have TLS negotiated to call this method!");
        nw_protocol_metadata_t p_metadata = nw_connection_copy_protocol_metadata(self.shared_state.connection, nw_protocol_copy_tls_definition());
        MLAssert(nw_protocol_metadata_is_tls(p_metadata), @"Protocol metadata is not TLS!");
        sec_protocol_metadata_t s_metadata = nw_tls_copy_sec_protocol_metadata(p_metadata);
        return sec_protocol_metadata_get_negotiated_tls_protocol_version(s_metadata) == tls_protocol_version_TLSv13;
    }
}

-(BOOL) acceptedTlsEarlyData
{
    @synchronized(self.shared_state) {
        MLAssert([self streamStatus] >= NSStreamStatusOpen && [self streamStatus] < NSStreamStatusClosed, @"Stream must be open to call this method!", (@{@"streamStatus": @([self streamStatus])}));
        MLAssert(self.shared_state.hasTLS, @"Stream must have TLS negotiated to call this method!");
        nw_protocol_metadata_t p_metadata = nw_connection_copy_protocol_metadata(self.shared_state.connection, nw_protocol_copy_tls_definition());
        MLAssert(nw_protocol_metadata_is_tls(p_metadata), @"Protocol metadata is not TLS!");
        sec_protocol_metadata_t s_metadata = nw_tls_copy_sec_protocol_metadata(p_metadata);
        return sec_protocol_metadata_get_early_data_accepted(s_metadata);
    }
}

-(NSData*) channelBindingData_TLSExporter
{
    @synchronized(self.shared_state) {
        MLAssert([self streamStatus] >= NSStreamStatusOpen && [self streamStatus] < NSStreamStatusClosed, @"Stream must be open to call this method!", (@{@"streamStatus": @([self streamStatus])}));
        MLAssert(self.shared_state.hasTLS, @"Stream must have TLS negotiated to call this method!");
        nw_protocol_metadata_t p_metadata = nw_connection_copy_protocol_metadata(self.shared_state.connection, nw_protocol_copy_tls_definition());
        MLAssert(nw_protocol_metadata_is_tls(p_metadata), @"Protocol metadata is not TLS!");
        sec_protocol_metadata_t s_metadata = nw_tls_copy_sec_protocol_metadata(p_metadata);
        //see https://www.rfc-editor.org/rfc/rfc9266.html
        return (NSData*)sec_protocol_metadata_create_secret(s_metadata, 24, "EXPORTER-Channel-Binding", 32);
    }
}

-(NSData*) channelBindingData_TLSServerEndPoint
{
    @synchronized(self.shared_state) {
        MLAssert([self streamStatus] >= NSStreamStatusOpen && [self streamStatus] < NSStreamStatusClosed, @"Stream must be open to call this method!", (@{@"streamStatus": @([self streamStatus])}));
        MLAssert(self.shared_state.hasTLS, @"Stream must have TLS negotiated to call this method!");
        nw_protocol_metadata_t p_metadata = nw_connection_copy_protocol_metadata(self.shared_state.connection, nw_protocol_copy_tls_definition());
        MLAssert(nw_protocol_metadata_is_tls(p_metadata), @"Protocol metadata is not TLS!");
        sec_protocol_metadata_t s_metadata = nw_tls_copy_sec_protocol_metadata(p_metadata);
        __block NSData* cert = nil;
        sec_protocol_metadata_access_peer_certificate_chain(s_metadata, ^(sec_certificate_t certificate) {
            if(cert == nil)
                cert = (__bridge_transfer NSData*)SecCertificateCopyData(sec_certificate_copy_ref(certificate));
        });
        MLCrypto* crypto = [MLCrypto new];
        NSString* signatureAlgo = [crypto getSignatureAlgoOfCert:cert];
        DDLogDebug(@"Signature algo OID: %@", signatureAlgo);
        //OIDs taken from https://www.rfc-editor.org/rfc/rfc3279#section-2.2.3 and "Updated by" RFCs
        if([@"1.2.840.113549.2.5" isEqualToString:signatureAlgo])               //md5WithRSAEncryption
            return [HelperTools sha256:cert];       //use sha256 as per RFC 5929
        else if([@"1.3.14.3.2.26" isEqualToString:signatureAlgo])               //sha1WithRSAEncryption
            return [HelperTools sha256:cert];       //use sha256 as per RFC 5929
        else if([@"1.2.840.113549.1.1.11" isEqualToString:signatureAlgo])       //sha256WithRSAEncryption
            return [HelperTools sha256:cert];
        else if([@"1.2.840.113549.1.1.12" isEqualToString:signatureAlgo])       //sha384WithRSAEncryption (not supported, return sha256, will fail cb)
        {
            DDLogError(@"Using sha256 for unsupported OID %@ (sha384WithRSAEncryption)", signatureAlgo);
            return [HelperTools sha256:cert];
        }
        else if([@"1.2.840.113549.1.1.13" isEqualToString:signatureAlgo])       //sha512WithRSAEncryption
            return [HelperTools sha512:cert];
        else if([@"1.2.840.113549.1.1.14" isEqualToString:signatureAlgo])       //sha224WithRSAEncryption (not supported, return sha256, will fail cb)
        {
            DDLogError(@"Using sha256 for unsupported OID %@ (sha224WithRSAEncryption)", signatureAlgo);
            return [HelperTools sha256:cert];
        }
        else if([@"1.2.840.10045.4.1" isEqualToString:signatureAlgo])           //ecdsa-with-SHA1
            return [HelperTools sha256:cert];       //use sha256 as per RFC 5929
        else if([@"1.2.840.10045.4.3.1" isEqualToString:signatureAlgo])         //ecdsa-with-SHA224  (not supported, return sha256, will fail cb)
        {
            DDLogError(@"Using sha256 for unsupported OID %@ (ecdsa-with-SHA224)", signatureAlgo);
            return [HelperTools sha256:cert];
        }
        else if([@"1.2.840.10045.4.3.2" isEqualToString:signatureAlgo])         //ecdsa-with-SHA256
            return [HelperTools sha256:cert];
        else if([@"1.2.840.10045.4.3.3" isEqualToString:signatureAlgo])         //ecdsa-with-SHA384  (not supported, return sha256, will fail cb)
        {
            DDLogError(@"Using sha256 for unsupported OID %@ (ecdsa-with-SHA384)", signatureAlgo);
            return [HelperTools sha256:cert];
        }
        else if([@"1.2.840.10045.4.3.4" isEqualToString:signatureAlgo])         //ecdsa-with-SHA512
            return [HelperTools sha512:cert];
        else if([@"1.3.6.1.5.5.7.6.32" isEqualToString:signatureAlgo])          //id-ecdsa-with-shake128  (not supported, return sha256, will fail cb)
        {
            DDLogError(@"Using sha256 for unsupported OID %@ (id-ecdsa-with-shake128)", signatureAlgo);
            return [HelperTools sha256:cert];
        }
        else if([@"1.3.6.1.5.5.7.6.33" isEqualToString:signatureAlgo])          //id-ecdsa-with-shake256  (not supported, return sha256, will fail cb)
        {
            DDLogError(@"Using sha256 for unsupported OID %@ (id-ecdsa-with-shake256)", signatureAlgo);
            return [HelperTools sha256:cert];
        }
        else        //all other algos use sha256 (that most probably will fail cb)
        {
            DDLogError(@"Using sha256 for unknown/unsupported OID: %@", signatureAlgo);
            return [HelperTools sha256:cert];
        }
    }
}

-(void) stream:(NSStream*) stream handleEvent:(NSStreamEvent) event
{
    //ignore event in this dummy delegate
    DDLogVerbose(@"ignoring event in dummy delegate: %@ --> %ld", stream, (long)event);
}

@end
