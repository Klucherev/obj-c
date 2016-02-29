

#import <CocoaLumberjack.h>

#import <VKSdk.h>

static const DDLogLevel ddLogLevel = DDLogLevelDebug;
NSString* const kVkontakteAuthProviderName = @"vkontakte";

typedef void(^CallbackLogin)(VKAccessToken *token, NSError* error);

@interface VkontakteAuthProvider() <VKSdkDelegate, VKSdkUIDelegate>
@property (strong           ) CallbackLogin callbackLogin;
@property (nonatomic, strong) UIWindow      *overWindow;
@property (nonatomic, assign) BOOL          inApp;

@end

@implementation VkontakteAuthProvider

@synthesize applicationId = _applicationId;
@synthesize secret        = _secret;

- (instancetype)init {
    NSString *vkAppId  = [[SocialConfiguration defaultConfiguration] objectForKey:@"VkontakteAppID"];
    NSString *vkSecret = [[SocialConfiguration defaultConfiguration] objectForKey:@"VkontakteSecret"];
    return [self initWithId:vkAppId secret:vkSecret];
}

- (instancetype)initWithId:(NSString *)applicationId secret:(NSString *)secret {
    NSParameterAssert(applicationId);
    NSParameterAssert(secret);
    
    self = [super init];
    if (self) {
        
        self->_applicationId = applicationId;
        self->_secret        = secret;
        
        DDLogVerbose(@"Initialize vkontake SDK");
        
        [[VKSdk initializeWithAppId:applicationId] registerDelegate:self];
        [[VKSdk instance] setUiDelegate:self];
        [VKSdk wakeUpSession:@[@"wall", @"photos"] completeBlock:^(VKAuthorizationState state, NSError *error) {
            NSLog(@"%lu", (unsigned long)state);
        }];
    }
    return self;
}

#pragma mark - ProviderProtocol
- (NSString *)name {
    return kVkontakteAuthProviderName;
}

- (NSString *)token {
    return [VKSdk accessToken].accessToken;
}

- (RACSignal *)logIn {
    @weakify(self);
    return [[RACSignal createSignal:^RACDisposable *(id<RACSubscriber> subscriber) {
        
        RACDisposable *errorDisposable = [[RACSignal merge:@[[[self rac_signalForSelector:@selector(vkSdkUserAuthorizationFailed) fromProtocol:@protocol(VKSdkDelegate)] mapReplace:[NSError errorWithDomain:kAGAuthErrorDomain code:AGAuthErrorCodesOperationCanceled userInfo:@{NSLocalizedDescriptionKey: @"Operation was canceled"}]],
                                                             ]] subscribeNext:^(id x) {
            [subscriber sendError:x];
        }];
        
        RACDisposable *updateTokeDisposable = [[self rac_signalForSelector:@selector(vkSdkAccessTokenUpdated:oldToken:) fromProtocol:@protocol(VKSdkDelegate)] subscribeNext:^(RACTuple *tuple) {
            
            VKAccessToken *token = tuple.first;
            AuthorizationCredentials *credentials = [AuthorizationCredentials externalCredentialsForProviderName:self.name];
            credentials.userId = token.userId;
            credentials.token = token.accessToken;
            [subscriber sendNext:credentials];
            [subscriber sendCompleted];
        }];
        
        RACDisposable *loginDisposable = [[self rac_signalForSelector:@selector(vkSdkAccessAuthorizationFinishedWithResult:) fromProtocol:@protocol(VKSdkDelegate)] subscribeNext:^(id result) {
            if ([result isKindOfClass:[RACTuple class]]) {
                RACTuple *tuple = result;
                VKAuthorizationResult *authResult = tuple.first;
                if (authResult.error) {
                    [subscriber sendError:authResult.error];
                } else {
                    [subscriber sendError:nil];
                }
            } else {
                VKAuthorizationResult *authResult = result;
                if (!authResult.error) {
                    AuthorizationCredentials *credentials = [AuthorizationCredentials externalCredentialsForProviderName:self.name];
                    credentials.userId = authResult.token.userId;
                    credentials.token = authResult.token.accessToken;
                    
                    [subscriber sendNext:credentials];
                    [subscriber sendCompleted];
                } else {
                    [subscriber sendError:authResult.error];
                }
            }
        }];
        
        @strongify(self);
        [self willChangeValueForKey:@keypath(self, isLoggedIn)];
        NSArray *permissions = @[@"wall", @"photos"];
        [VKSdk authorize:permissions withOptions:VKAuthorizationOptionsUnlimitedToken];
        
        return [RACDisposable disposableWithBlock:^{
            [errorDisposable dispose];
            [updateTokeDisposable dispose];
            [loginDisposable dispose];
        }];
    }] finally:^{
        @strongify(self);
        [self didChangeValueForKey:@keypath(self, isLoggedIn)];
    }];
            
}

- (RACSignal *)logOut {
    DDLogVerbose(@"Logging out from vkontake");
    [self willChangeValueForKey:@keypath(self, isLoggedIn)];
    [VKSdk forceLogout];
    [self didChangeValueForKey:@keypath(self, isLoggedIn)];
    return [RACSignal return:nil];
}


- (RACSignal *)getUserInfo {
    return [RACSignal createSignal:^RACDisposable *(id<RACSubscriber> subscriber) {
        VKApiUsers *apiUsers    = [VKApi users];
        VKRequest *request      = [apiUsers get:@{@"fields": @"sex, bdate, city, country, photo_max_orig, about, personal"}];

        [request executeWithResultBlock:^(VKResponse *response) {
            NSDictionary* json = response.json[0];
            
            if (![json isKindOfClass:[NSDictionary class]]) {
                NSError* error = [NSError errorWithDomain:kAGAuthErrorDomain
                                                     code:AGAuthErrorCodesMalformedResponse
                                                 userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"%@ arrived when %@ expected", json.class, [NSDictionary class]]}];
                
                DDLogError(@"%@", error);
                [subscriber sendError: error];
                return;
            }

            SocialProfile* profile = [SocialProfile new];
            profile.provider = self.name;
            
            NSDictionary *converter = @{@keypath(profile, identifier):@"id",
                                        @keypath(profile, firstName) :@"first_name",
                                        @keypath(profile, lastName)  :@"last_name",
                                        @keypath(profile, name)      :@"name",
                                        @keypath(profile, avatarUrl) :@"photo_max_orig",
                                        @keypath(profile, bio)       :@"about"};
            
            [profile loadObject:json withConvertionTable:converter];
            
            NSString* birthdayString = json[@"bdate"];
            if (birthdayString) {
                static NSDateFormatter* dateFormatter;
                if (!dateFormatter) {
                    dateFormatter = [[NSDateFormatter alloc] init];
                    dateFormatter.dateFormat = @"dd.MM.yyyy";
                }
                profile.birthdayDate =[dateFormatter dateFromString:birthdayString];
            }
            
            if (!profile.name) {
                NSMutableArray* parts = [NSMutableArray array];
                if (profile.firstName) [parts addObject:profile.firstName];
                if (profile.lastName) [parts addObject:profile.lastName];
                
                if (parts.count > 0) {
                    profile.name = [parts componentsJoinedByString:@" "];
                }
            }
            
            NSNumber* sex = [json valueForKeyPath:@"sex"];
            if (sex) {
                if (sex.integerValue == 1) {
                    profile.gender = [Gender women];
                } else if (sex.integerValue == 2) {
                    profile.gender = [Gender men];
                } else {
                    profile.gender = [Gender unknown];
                }
            }
            
            [subscriber sendNext:profile];
            [subscriber sendCompleted];
        } errorBlock:^(NSError *error) {
            [subscriber sendError:error];
        }];
        return nil;
    }];
}

- (BOOL)isLoggedIn {
    return [VKSdk accessToken].accessToken != nil;
}

- (BOOL)application:(UIApplication *)application openURL:(NSURL *)url sourceApplication:(NSString *)sourceApplication annotation:(id)annotation {
    if (![url.scheme hasPrefix:@"vk"]) {
        return NO;
    }
    
    DDLogDebug(@"Process url with vkontakte handler");
    return [VKSdk processOpenURL: url fromApplication: sourceApplication];
}

- (BOOL)application:(UIApplication *)app openURL:(NSURL *)url options:(NSDictionary<NSString *,id> *)options {
    if (![url.scheme hasPrefix:@"vk"]) {
        return NO;
    }
    [VKSdk processOpenURL:url fromApplication:options[UIApplicationOpenURLOptionsSourceApplicationKey]];
    return YES;
}

- (void)applicationDidBecomeActive:(UIApplication *)application {
    if (self.inApp) {
        return;
    }
    
    if (self.loginSubject) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            NSError* error = [NSError errorWithDomain:kAGAuthErrorDomain
                                                 code:AGAuthErrorCodesOperationCanceled
                                             userInfo:@{NSLocalizedDescriptionKey: @"Operation was canceled"}];
            [self.loginSubject sendError:error];
            self.loginSubject = nil;
        });
    }
}

#pragma mark - VKSdkDelegate


- (void)vkSdkNeedCaptchaEnter:(VKError*) captchaError {
    VKCaptchaViewController * vc = [VKCaptchaViewController captchaControllerWithError:captchaError];
    UIViewController *topVC = [UIApplication sharedApplication].keyWindow.rootViewController;
    [vc presentIn:topVC];
}

- (void)vkSdkTokenHasExpired:(VKAccessToken *)expiredToken {
    [VKSdk authorize:@[] withOptions:0];
}

- (void)vkSdkShouldPresentViewController:(UIViewController *)controller {
    
    [[UIApplication sharedApplication].keyWindow.rootViewController presentViewController:controller animated:YES completion:nil];
}


#pragma mark - Share

-(RACSignal*)sharePhoto:(UIImage*)photo withTitle:(NSString*)title fromViewController:(UIViewController*)controller  {
    @weakify(self);
    if ([self isLoggedIn]) {
        @strongify(self);
        AuthorizationCredentials *credentials = [AuthorizationCredentials externalCredentialsForProviderName:self.name];
        credentials.userId = [[VKSdk accessToken] userId];
        return [[[self uploadPhotoToWall:photo withCredentials:credentials] flattenMap:^RACStream *(VKResponse *response) {
            return [self postPhotoToWallFromResponse:response withCredentials:credentials withPhotoTitle:title];
        }] catch:^RACSignal *(NSError *error) {
            return [[self logIn] flattenMap:^RACStream *(AuthorizationCredentials *credentials) {
                @strongify(self);
                return [[self uploadPhotoToWall:photo withCredentials:credentials] flattenMap:^RACStream *(VKResponse *response) {
                    return [self postPhotoToWallFromResponse:response withCredentials:credentials withPhotoTitle:title];
                }];
            }];
        }];
    } else {
        return [[self logIn] flattenMap:^RACStream *(AuthorizationCredentials *credentials) {
            @strongify(self);
            return [[self uploadPhotoToWall:photo withCredentials:credentials] flattenMap:^RACStream *(VKResponse *response) {
                return [self postPhotoToWallFromResponse:response withCredentials:credentials withPhotoTitle:title];
            }];
        }];
    }
}

- (RACSignal *)uploadPhotoToWall:(UIImage*)photo withCredentials:(AuthorizationCredentials*)credentials{
    @weakify(self);
    RACSignal *postToWallSignal = [RACSignal createSignal:^RACDisposable *(id<RACSubscriber> subscriber) {
        @strongify(self);
        VKRequest *request = [VKApi uploadWallPhotoRequest:photo parameters:[VKImageParameters jpegImageWithQuality:1.f] userId:credentials.userId.integerValue groupId:nil ];
        [request executeWithResultBlock:^(VKResponse * response) {
            [subscriber sendNext:response];
            [subscriber sendCompleted];
            NSLog(@"Json result: %@", response.json);
        } errorBlock:^(NSError * error) {
            if (error.code != VK_API_ERROR) {
                [error.vkError.request repeat];
            } else {
                [subscriber sendError:error];
            } 
        }];
        
        return [RACDisposable disposableWithBlock:^{
            [request cancel];
        }];
    }];
    
    return [postToWallSignal deliverOnMainThread];
}

- (RACSignal *)postPhotoToWallFromResponse:(VKResponse*)response withCredentials:(AuthorizationCredentials*)credentials withPhotoTitle:(NSString*)title{
    @weakify(self);
    RACSignal *savePhotoToWallSignal = [RACSignal createSignal:^RACDisposable *(id<RACSubscriber> subscriber) {
        @strongify(self);
        VKPhoto *photoInfo = [(VKPhotoArray*)response.parsedModel objectAtIndex:0];
        NSString *photoAttachment = [NSString stringWithFormat:@"photo%@_%@", photoInfo.owner_id, photoInfo.id];
        NSString *message = (title.length>0) ?: title;
        VKRequest *postReq = [[VKApi wall] post:@{VK_API_ATTACHMENTS : photoAttachment, VK_API_OWNER_ID : credentials.userId, VK_API_MESSAGE : message}];
        [postReq executeWithResultBlock:^(VKResponse * response) {
            [subscriber sendNext:response];
            [subscriber sendCompleted];
            NSLog(@"Json result: %@", response.json);
        } errorBlock:^(NSError * error) {
            if (error.code != VK_API_ERROR) {
                [error.vkError.request repeat];
            } else {
                [subscriber sendError:error];
            }
        }];
        
        return [RACDisposable disposableWithBlock:^{
            [postReq cancel];
        }];
    }];
    
    return [savePhotoToWallSignal deliverOnMainThread];
}


- (RACSignal *)getPhotoUploadUrlWithCredentials:(AuthorizationCredentials*)credentials {
    NSString *getWallUploadServer = [NSString stringWithFormat:@"https://api.vk.com/method/photos.getWallUploadServer?owner_id=%@&access_token=%@", credentials.userId, credentials.token];
    return [[self sendRequestWith:getWallUploadServer] flattenMap:^RACStream *(NSDictionary *responseDict) {
        NSString *upload_url = [[responseDict objectForKey:@"response"] objectForKey:@"upload_url"];
        if (!upload_url) {
            return [RACSignal error:nil];
        }
        return [RACSignal return:upload_url];
    }];
}

- (RACSignal *)sendRequestWith:(NSString*)requestString {
    RACSignal *requestSignal = [RACSignal createSignal:^RACDisposable *(id<RACSubscriber> subscriber) {
        NSMutableURLRequest *urlRequest = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:requestString]];
        urlRequest.HTTPMethod = @"GET";
        AFHTTPRequestOperation *requestOperation = [[AFHTTPRequestOperation alloc] initWithRequest:urlRequest];
        requestOperation.responseSerializer = [AFJSONResponseSerializer new];
        [requestOperation setCompletionBlockWithSuccess:^(AFHTTPRequestOperation *operation, id responseObject) {
            
            [subscriber sendNext:responseObject];
            
        } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
            if (operation.isCancelled) {
                [subscriber sendCompleted];
            }
            else {
                [subscriber sendError:error];
            }
        }];
        
        [requestOperation start];
        
        return [RACDisposable disposableWithBlock:^{
            [requestOperation cancel];
        }];
        
    }];
    
    return [requestSignal deliverOnMainThread];
}

- (RACSignal *)sendPostRequest:(NSString*)url withImageData:(NSData*)data {
    
    @weakify(self);
    RACSignal *requestSignal = [RACSignal createSignal:^RACDisposable *(id<RACSubscriber> subscriber) {
        @strongify(self);
        AFHTTPRequestOperationManager* manager = [AFHTTPRequestOperationManager new];
        manager.responseSerializer = [AFJSONResponseSerializer serializer];
        AFHTTPRequestOperation *operation = [manager POST:url parameters:nil constructingBodyWithBlock:^(id<AFMultipartFormData> formData) {
            [formData appendPartWithFileData:data name:@"photo" fileName:@"photo.jpg" mimeType:@"image/jpeg"];
        } success:^(AFHTTPRequestOperation *operation, id responseObject) {
            NSInteger httpStatus = operation.response.statusCode;
            NSString *test = [[NSString alloc] initWithData:responseObject encoding:NSUTF8StringEncoding];
            DDLogVerbose(@"HTTP[%p] Response: %ld: %@", url, (long)httpStatus, responseObject);
            [subscriber sendNext:responseObject];
            [subscriber sendCompleted];
        } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
            DDLogError(@"HTTP[%p] Error: %@", url, error);
            [subscriber sendError:error];
        }];
        
        return [RACDisposable disposableWithBlock:^{
            [operation cancel];
        }];
    }];
    
    return [requestSignal deliverOnMainThread];
}

@end
