//
//  untethered.m
//  Athenus
//
// any code placed in fun(...) will be executed untethered

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#include "config.h"
#include "jailbreak.h"
#include <sys/utsname.h>
#include <time.h>
#include <errno.h>
#include <sys/sysctl.h>
#include <dlfcn.h>
#import "sugondesenuts.h"

int (*dsystem)(const char *) = 0;

void jelbrekme() {
    dispatch_async(jailbreak_queue , ^{
        sleep(2);
        if (viewDidExecute)
            return;
        struct utsname name;
        uname(&name);
        if (!strstr(name.version, "MarijuanARM")){
            usleep(USEC_PER_SEC/100);
            jailbreak();
        }
    });
}

int fun(int argc, char* argv[]) {
    dsystem = dlsym(RTLD_DEFAULT,"system");
    
    /* enable logging */
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,NSUserDomainMask, YES);
    NSString *documentsDirectory = [paths objectAtIndex:0];
    NSString *fileName =[NSString stringWithFormat:@"%@.txt",[NSDate date]];
    NSString *logFilePath = [documentsDirectory stringByAppendingPathComponent:fileName];
    freopen([logFilePath cStringUsingEncoding:NSASCIIStringEncoding],"a+",stdout);
    freopen([logFilePath cStringUsingEncoding:NSASCIIStringEncoding],"a+",stderr);
    NSLog(@"loaded");
    
    /* do teh jelbrekz */
    dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^(void){
        __block UIBackgroundTaskIdentifier backgroundTaskIdentifier = [[UIApplication sharedApplication] beginBackgroundTaskWithExpirationHandler:^{
            
            [[UIApplication sharedApplication] endBackgroundTask:backgroundTaskIdentifier];
            
            backgroundTaskIdentifier = UIBackgroundTaskInvalid;
        }];
        jelbrekme();
    });
    return 0;
}
