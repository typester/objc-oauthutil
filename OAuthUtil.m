#import "OAuthUtil.h"

#import <Security/Security.h>
#import <Security/SecRandom.h>
#import <CommonCrypto/CommonHMAC.h>

static const char hex[] = "0123456789abcdef";

@interface NSData ()
- (NSString *)base64Encoding;
@end

@implementation OAuthUtil

@synthesize key = key_, secret = secret_;

-(id)initWithKey:(NSString*)key secret:(NSString*)secret {
    self = [super init];
    if (self) {
        self.key    = key;
        self.secret = secret;
    }
    return self;
}

-(void)dealloc {
    self.key    = nil;
    self.secret = nil;
    [super dealloc];
}


static inline NSString* encode_param(NSString* s) {
    return ((NSString*)CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault,
                (CFStringRef)s,
                NULL,
                (CFStringRef)@"!*'();:@&=+$,/?%#[]",
                kCFStringEncodingUTF8));
}

static NSData* HMAC_SHA1(NSString* data, NSString* key) {
    unsigned char buf[CC_SHA1_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA1, [key UTF8String], [key length],
        [data UTF8String], [data length], buf);
    return [NSData dataWithBytes:buf length:CC_SHA1_DIGEST_LENGTH];
}

-(NSDictionary*)authParamsWithMethod:(NSString*)method
                                 url:(NSURL*)url
                               token:(NSString*)token
                              secret:(NSString*)secret
                               extra:(NSDictionary*)extra {

    int i, r;
    uint8_t bytes[10], str[20 + 1];

    NSNumber* time = [NSNumber numberWithUnsignedLong:(unsigned long)[[NSDate date] timeIntervalSince1970]];

    r = SecRandomCopyBytes(kSecRandomDefault, 10, bytes);
    NSAssert(0 == r, nil);

    for (i = 0; i < 10; i++) {
        str[i*2]     = hex[ (bytes[i] >> 4) & 0xf ];
        str[i*2 + 1] = hex[ bytes[i] & 0xf ];
    }
    str[20] = '\0';

    NSString* nonce = [NSString stringWithUTF8String:(const char*)str];

    NSMutableDictionary* p =
        [NSMutableDictionary dictionaryWithObjectsAndKeys:
                                 self.key,       @"oauth_consumer_key",
                             [time stringValue], @"oauth_timestamp",
                             nonce,              @"oauth_nonce",
                             @"1.0",             @"oauth_version",
                             @"HMAC-SHA1",       @"oauth_signature_method",
                             nil];
    if (token) {
        [p setObject:token forKey:@"oauth_token"];
    }
    if (extra) {
        for (NSString* k in [extra allKeys]) {
            [p setObject:[extra objectForKey:k] forKey:k];
        }
    }

    NSString* base = [self createSignatureBaseStringWithMethod:method
                                                           url:url
                                                        params:p];

    if (!secret)
        secret = @"";
    NSString* sig_key = [[NSArray arrayWithObjects:
                                     encode_param(self.secret), encode_param(secret), nil]
                            componentsJoinedByString:@"&"];
    NSData* sig = HMAC_SHA1(base, sig_key);
    NSString* base64sig = [sig base64Encoding];

    [p setObject:base64sig forKey:@"oauth_signature"];

    return [NSDictionary dictionaryWithDictionary:p];
}

-(NSString*)createSignatureBaseStringWithMethod:(NSString*)method
                                            url:(NSURL*)url
                                         params:(NSDictionary*)params {

    NSArray* keys = [params allKeys];
    NSSortDescriptor* sort = [[NSSortDescriptor alloc] initWithKey:@"text" ascending:YES];
    NSArray* sortDescs = [NSArray arrayWithObjects:sort, nil];

    keys = [keys sortedArrayUsingSelector:@selector(localizedCaseInsensitiveCompare:)];
    [sort release];

    NSMutableArray* pairs = [NSMutableArray array];
    for (NSString* k in keys) {
        [pairs addObject:[NSString stringWithFormat:@"%@=%@",
                                   encode_param(k), encode_param([params objectForKey:k])]];
    }

    NSString* normalized_params = [pairs componentsJoinedByString:@"&"];

    return [[NSArray arrayWithObjects:
                         encode_param(method),
                     encode_param([url absoluteString]),
                     encode_param(normalized_params), nil]
                                componentsJoinedByString:@"&"];
}

-(NSString*)buildAuthHeaderWithRealm:(NSString*)realm
                              params:(NSDictionary*)params {

    NSMutableArray* headers = [NSMutableArray array];
    for (NSString* key in [params allKeys]) {
        NSString* s = [NSString stringWithFormat:@"%@=\"%@\"",
                                encode_param(key), encode_param([params objectForKey:key])];
        [headers addObject:s];
    }

    NSString* header = [NSString stringWithFormat:@"OAuth realm=\"%@\", %@",
                                 encode_param(realm),
                                 [[headers sortedArrayUsingSelector:@selector(localizedCaseInsensitiveCompare:)] componentsJoinedByString:@", "]];
    return header;
}

@end

// http://www.cocoadev.com/index.pl?BaseSixtyFour
static const char encodingTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

@implementation NSData (MBBase64)

-(NSString *)base64Encoding {
    if ([self length] == 0)
        return @"";

    char *characters = malloc((([self length] + 2) / 3) * 4);
    if (characters == NULL)
        return nil;
    NSUInteger length = 0;

    NSUInteger i = 0;
    while (i < [self length]) {
        char buffer[3] = {0,0,0};
        short bufferLength = 0;
        while (bufferLength < 3 && i < [self length])
            buffer[bufferLength++] = ((char *)[self bytes])[i++];

        //  Encode the bytes in the buffer to four characters, including padding "=" characters if necessary.
        characters[length++] = encodingTable[(buffer[0] & 0xFC) >> 2];
        characters[length++] = encodingTable[((buffer[0] & 0x03) << 4) | ((buffer[1] & 0xF0) >> 4)];
        if (bufferLength > 1)
            characters[length++] = encodingTable[((buffer[1] & 0x0F) << 2) | ((buffer[2] & 0xC0) >> 6)];
        else
            characters[length++] = '=';

        if (bufferLength > 2)
            characters[length++] = encodingTable[buffer[2] & 0x3F];
        else
            characters[length++] = '=';
    }

    return [[[NSString alloc] initWithBytesNoCopy:characters length:length encoding:NSASCIIStringEncoding freeWhenDone:YES] autorelease];
}

@end
