

#import <UIKit/UIKit.h>
#import "AGProviderProtocol.h"
#import "AGAuthManager.h"

extern NSString* const kVkontakteAuthProviderName;

@interface VkontakteAuthProvider : NSObject<ProviderProtocol>
-(instancetype) initWithId:(NSString *)applicationId secret:(NSString *)secret;
@end
