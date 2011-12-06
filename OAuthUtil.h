#import <Foundation/Foundation.h>

@interface OAuthUtil : NSObject

@property (nonatomic, copy) NSString* key;
@property (nonatomic, copy) NSString* secret;

-(id)initWithKey:(NSString*)key secret:(NSString*)secret;

-(NSDictionary*)authParamsWithMethod:(NSString*)method
                                 url:(NSURL*)url
                               token:(NSString*)token
                              secret:(NSString*)secret
                               extra:(NSDictionary*)extra;

-(NSString*)createSignatureBaseStringWithMethod:(NSString*)method
                                            url:(NSURL*)url
                                         params:(NSDictionary*)params;

-(NSString*)buildAuthHeaderWithRealm:(NSString*)realm
                              params:(NSDictionary*)params;

@end
