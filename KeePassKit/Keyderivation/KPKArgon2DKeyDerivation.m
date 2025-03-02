//
//  KPKAnon2KeyDerivation.m
//  KeePassKit
//
//  Created by Michael Starke on 13/09/16.
//  Copyright © 2016 HicknHack Software GmbH. All rights reserved.
//

#import "KPKArgon2DKeyDerivation.h"
#import "KPKKeyDerivation_Private.h"

#import "KPKNumber.h"

#import "NSData+KPKRandom.h"
#import "NSDictionary+KPKVariant.h"

#import "argon2.h"

NSString *const KPKArgon2DSaltParameter             = @"S";
NSString *const KPKArgon2DParallelismParameter      = @"P";
NSString *const KPKArgon2DMemoryParameter           = @"M";
NSString *const KPKArgon2DIterationsParameter       = @"I";
NSString *const KPKArgon2DVersionParameter          = @"V";
NSString *const KPKArgon2DSecretKeyParameter        = @"K";
NSString *const KPKArgon2DAssociativeDataParameter  = @"A";

const uint32_t KPKArgon2DMinSaltLength = 8;
const uint32_t KPKArgon2DMaxSaltLength = INT32_MAX;
const uint64_t KPKArgon2DMinIterations = 1;
const uint64_t KPKArgon2DMaxIterations = UINT32_MAX;

const uint64_t KPKArgon2DMinMemory = 1024 * 8;
const uint64_t KPKArgon2DMaxMemory = INT32_MAX;

const uint32_t KPKArgon2DMinParallelism = 1;
const uint32_t KPKArgon2DMaxParallelism = (1 << 24) - 1;

const uint64_t KPKArgon2DDefaultIterations = 2;
const uint64_t KPKArgon2DDefaultMemory = 1024 * 1024; // 1 MB
const uint32_t KPKArgon2DDefaultParallelism = 2;

#define KPK_ARGON2_CHECK_INVERVALL(min,max,value) ( (value >= min) && (value <= max) )

@implementation KPKArgon2DKeyDerivation

+ (void)load {
  [KPKKeyDerivation _registerKeyDerivation:self];
}

+ (NSUUID *)uuid {
  static const uuid_t bytes = {
    0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B,
    0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C
  };
  static NSUUID *argon2dUUID = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    argon2dUUID = [[NSUUID alloc] initWithUUIDBytes:bytes];
  });
  return argon2dUUID;
}

+ (KPKArgon2Type)type {
  return KPKArgon2TypeD;
}

+ (NSDictionary *)defaultParameters {
  NSMutableDictionary *parameters = [[super defaultParameters] mutableCopy];
  [parameters setUnsignedInteger32:ARGON2_VERSION_13 forKey:KPKArgon2DVersionParameter];
  [parameters setUnsignedInteger64:KPKArgon2DDefaultIterations forKey:KPKArgon2DIterationsParameter];
  [parameters setUnsignedInteger64:KPKArgon2DDefaultMemory forKey:KPKArgon2DMemoryParameter];
  [parameters setUnsignedInteger32:KPKArgon2DDefaultParallelism forKey:KPKArgon2DParallelismParameter];
  return [parameters copy];
}

- (NSString *)name {
  return @"Argon2d";
}

- (uint64_t)iterations {
  return [self.mutableParameters unsignedInteger64ForKey:KPKArgon2DIterationsParameter];
}

- (void)setIterations:(uint64_t)iterations {
  [self.mutableParameters setUnsignedInteger64:iterations forKey:KPKArgon2DIterationsParameter];
}

- (uint32_t)threads {
  return [self.mutableParameters unsignedInteger32ForKey:KPKArgon2DParallelismParameter];
}

- (void)setThreads:(uint32_t)threads {
  [self.mutableParameters setUnsignedInteger32:threads forKey:KPKArgon2DParallelismParameter];
}

- (uint64_t)memory {
  return [self.mutableParameters unsignedInteger64ForKey:KPKArgon2DMemoryParameter];
}

- (void)setMemory:(uint64_t)memory {
  [self.mutableParameters setUnsignedInteger64:memory forKey:KPKArgon2DMemoryParameter];
}

- (uint64_t)minimumMemory {
  return KPKArgon2DMaxMemory;
}

- (uint64_t)maximumMemory {
  return KPKArgon2DMaxMemory;
}

- (void)randomize {
  [self.mutableParameters setData:[NSData kpk_dataWithRandomBytes:32] forKey:KPKArgon2DSaltParameter];
}

- (BOOL)adjustParameters:(NSMutableDictionary *)parameters {
  BOOL changed = NO;
  KPKNumber *p = parameters[KPKArgon2DParallelismParameter];
  if(p) {
    uint32_t clamped = MIN(MAX(KPKArgon2DMinParallelism, p.unsignedInteger32Value), KPKArgon2DMaxParallelism);
    if(clamped != p.unsignedInteger32Value) {
      changed = YES;
      [parameters setUnsignedInteger32:clamped forKey:KPKArgon2DParallelismParameter];
    }
  }

  KPKNumber *i = parameters[KPKArgon2DIterationsParameter];
  if(i) {
    uint64_t clamped = MIN(MAX(KPKArgon2DMinIterations, p.unsignedInteger64Value), KPKArgon2DMaxIterations);
    if(clamped != i.unsignedInteger64Value) {
      changed = YES;
      [parameters setUnsignedInteger64:clamped forKey:KPKArgon2DIterationsParameter];
    }
  }

  KPKNumber *m = parameters[KPKArgon2DMemoryParameter];
  if(i) {
    uint64_t clamped = MIN(MAX(KPKArgon2DMinMemory, m.unsignedInteger64Value), KPKArgon2DMaxMemory);
    if(clamped != m.unsignedInteger64Value) {
      changed = YES;
      [parameters setUnsignedInteger64:clamped forKey:KPKArgon2DMemoryParameter];
    }
  }
  return changed;
}

- (NSData *)deriveData:(NSData *)data {
  NSAssert(self.mutableParameters[KPKArgon2DIterationsParameter], @"Iterations option is missing!");
  NSAssert(self.mutableParameters[KPKArgon2DSaltParameter], @"Salt option is missing!");
  NSAssert(self.mutableParameters[KPKArgon2DMemoryParameter], @"Memory option is missing!");
  NSAssert(self.mutableParameters[KPKArgon2DParallelismParameter], @"Parallelism option is missing!");
  NSAssert(self.mutableParameters[KPKArgon2DVersionParameter], @"Version option is missing!");
  
  uint32_t version = [self.mutableParameters unsignedInteger32ForKey:KPKArgon2DVersionParameter];
  if(!KPK_ARGON2_CHECK_INVERVALL(ARGON2_VERSION_10, ARGON2_VERSION_13, version)) {
    return nil;
  }
  
  NSData *saltData = [self.mutableParameters dataForKey:KPKArgon2DSaltParameter];
  if(!KPK_ARGON2_CHECK_INVERVALL(KPKArgon2DMinSaltLength, KPKArgon2DMaxSaltLength, saltData.length)) {
    return nil;
  }
  uint32_t parallelism = self.threads;
  if(!KPK_ARGON2_CHECK_INVERVALL(KPKArgon2DMinParallelism, KPKArgon2DMaxParallelism, parallelism)) {
    return nil;
  }
  
  uint64_t memory = self.memory;
  if(!KPK_ARGON2_CHECK_INVERVALL(KPKArgon2DMinMemory, KPKArgon2DMaxMemory, memory)) {
    return nil;
  }
  uint64_t iterations = self.iterations;
  if(!KPK_ARGON2_CHECK_INVERVALL(KPKArgon2DMinIterations, KPKArgon2DMaxIterations, iterations)) {
    return nil;
  }
  
  NSData *associativeData = [self.mutableParameters dataForKey:KPKArgon2DAssociativeDataParameter];
  NSData *secretData = [self.mutableParameters dataForKey:KPKArgon2DSecretKeyParameter];

  uint8_t hash[32];
  argon2_context context = {
    hash,  /* output array, at least HASHLEN in size */
    sizeof(hash), /* digest length */
    (uint8_t *)data.bytes, /* password array */
    (uint32_t)data.length, /* password length */
    (uint8_t *)saltData.bytes, /* salt array */
    (uint32_t)saltData.length, /* salt length */
    NULL, 0, /* optional secret data */
    NULL, 0, /* optional associated data */
    (uint32_t)iterations,
    (uint32_t)(memory/1024),
    parallelism,
    parallelism,
    version, /* algorithm version */
    NULL, NULL, /* custom memory allocation / deallocation functions */
    ARGON2_DEFAULT_FLAGS /* by default the password is zeroed on exit */
  };
  
  /* Optionals */
  if(associativeData) {
    context.ad = (uint8_t *)associativeData.bytes;
    context.adlen = (uint32_t)associativeData.length;
  }
  if(secretData) {
    context.secret = (uint8_t *)secretData.bytes;
    context.secretlen = (uint32_t)secretData.length;
  }
  
  int returnCode = ARGON2_OK;
  if(self.class.type == KPKArgon2TypeD) {
    returnCode = argon2d_ctx(&context);;
  }
  else if(self.class.type == KPKArgon2TypeID) {
    returnCode = argon2id_ctx(&context);
  }
  else {
    NSLog(@"Unknown Argon2 key derivation type");
    return nil;
  }
  
  if(ARGON2_OK != returnCode) {
    NSLog(@"%s", argon2_error_message(returnCode));
    return nil;
  }
  return [NSData dataWithBytes:hash length:sizeof(hash)];
}

@end
