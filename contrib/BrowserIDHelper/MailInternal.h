@interface MCSASLClient : NSObject
{
}
+ (id)newSASLClientWithMechanismName:mechName account:arg2 externalSecurityLayer:(unsigned int)layer;
@end

@class NSSocket;

@interface MCConnection : NSObject
{
}
- (id)authenticationMechanisms;
@end
