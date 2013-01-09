@protocol MVMessageDisplayNotifications

@optional
- (void)messageWillBeDisplayedInView:(id)arg1;
@end

@interface MVMailBundle : NSObject <MVMessageDisplayNotifications>
{
}
@end

@protocol CMFAccount;

@interface SASLClient : NSObject
{
}
+ (id)newSASLClientWithMechanismName:mechName account:arg2 externalSecurityLayer:(unsigned int)layer;
@property(copy, nonatomic) NSString *mechanismName; // @synthesize mechanismName=_mechanismName;
@end

@class NSSocket;

@interface Connection : NSObject
{
}
- (id)authenticationMechanisms;
@end

@class IMAPMailbox;
@class IMAPGateway;
@class InvocationQueue;

@interface IMAPConnection : Connection
{
}
@end
