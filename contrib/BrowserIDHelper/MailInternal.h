@interface SASLClient : NSObject
{
}
+ (id)newSASLClientWithMechanismName:mechName account:arg2 externalSecurityLayer:(unsigned int)layer;
@end

@class NSSocket;

@interface Connection : NSObject
{
}
- (id)authenticationMechanisms;
@end

@interface IMAPConnection : Connection
{
}
@end
