@protocol MVMessageDisplayNotifications

@optional
- (void)messageWillBeDisplayedInView:(id)arg1;
@end

@interface MVMailBundle : NSObject <MVMessageDisplayNotifications>
{
}

+ (id)composeAccessoryViewOwnerClassName;
+ (BOOL)hasComposeAccessoryViewOwner;
+ (id)preferencesPanelName;
+ (id)preferencesOwnerClassName;
+ (BOOL)hasPreferencesPanel;
+ (id)sharedInstance;
+ (void)registerBundle;
+ (id)composeAccessoryViewOwners;
+ (id)allBundles;
- (void)_registerBundleForNotifications;
- (void)dealloc;

@end

@protocol CMFAccount;

@interface SASLClient : NSObject
{
    NSString *_mechanismName;
    id <CMFAccount> _account;
    long long _authenticationState;
    unsigned int _encryptionBufferSize;
    BOOL _justSentPlainTextPassword;
}

+ (id)allocWithZone:(NSZone *)zone;
+ (id)newSASLClientWithMechanismName:mechName account:arg2 externalSecurityLayer:(unsigned int)layer;
+ (void)initializeSASLClient;
@property(nonatomic) unsigned int encryptionBufferSize; // @synthesize encryptionBufferSize=_encryptionBufferSize;
@property(nonatomic) BOOL justSentPlainTextPassword; // @synthesize justSentPlainTextPassword=_justSentPlainTextPassword;
@property(nonatomic) long long authenticationState; // @synthesize authenticationState=_authenticationState;
@property(retain, nonatomic) id <CMFAccount> account; // @synthesize account=_account;
@property(copy, nonatomic) NSString *mechanismName; // @synthesize mechanismName=_mechanismName;
- (BOOL)resetWithExternalSecurityLayer:(unsigned int)layer;
- (void)dealloc;

@end

@class NSSocket;

@interface Connection : NSObject
{
    double _connectTimeout;
    double _readWriteTimeout;
    id <CMFAccount> _account;
    NSSocket *_socket;
    void *_buffer;
    long long _bufferRemainingBytes;
    unsigned long long _bufferStart;
    unsigned long long _bufferLength;
    NSData *_logHeader;
    SASLClient *_saslClient;
}
- (id)authenticationMechanisms;
@end

@class IMAPMailbox;
@class IMAPGateway;
@class InvocationQueue;

@interface IMAPConnection : Connection
{
    NSRecursiveLock *_imapConnectionLock;
    unsigned long long _capabilityFlags;
    int _connectionState;
    NSMutableSet *_capabilities;
    NSString *_separatorChar;
    NSString *_selectedMailbox;
    IMAPMailbox *_selectedIMAPMailbox;
    BOOL _selectedMailboxIsReadOnly;
    BOOL _canStartIdle;
    unsigned long long _commandNumber;
    unsigned int _readBufferSize;
    double _expirationTime;
    InvocationQueue *_streamEventQueue;
    NSMutableDictionary *_unhandledTaggedResponses;
    unsigned long long _fetchSizeNextReadingIndex;
    double _fetchSizeRollingAverage;
    BOOL _fetchSizeFirstTime;
    BOOL _fetchSizeFilledHistory;
    double _fetchSizeRecentTimes[8];
    IMAPGateway *_gateway;
    NSRecursiveLock *_validatingLock;
    unsigned long long _lastIdleSequenceNumber;
    unsigned long long _lastIdleSessionNumber;
    BOOL _createsGateway;
    BOOL _executingInternalReconnect;
    BOOL _sentID;
}
@end
