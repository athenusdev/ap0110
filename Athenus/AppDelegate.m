/*
 *                   ___  _ _  ___
 *       __ _ _ __  / _ \/ / |/ _ \
 *      / _` | '_ \| | | | | | | | |
 *     | (_| | |_) | |_| | | | |_| |
 *      \__,_| .__/ \___/|_|_|\___/
 *           |_|
 *
 *        ap0110 is an autoexecuting jailbreak for iOS 10.x, on 64 and 32 bit.
 *        Licensed under GPLv2, fuck v3.
 *        Fuck manticore and iMuseum
 *
 *         - with love from the Athenus Dev Team and w212.
 */

#import "AppDelegate.h"
#include "untethered.h"
#include "config.h"
#include "jailbreak.h"
#include <sys/utsname.h>
#include <time.h>
#include <errno.h>
#include <sys/sysctl.h>
#include <dlfcn.h>

@interface AppDelegate ()

@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    fun(0,0);
    return YES;
}


- (void)applicationWillResignActive:(UIApplication *)application {
    // Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
    // Use this method to pause ongoing tasks, disable timers, and throttle down OpenGL ES frame rates. Games should use this method to pause the game.
}

- (void)applicationDidEnterBackground:(UIApplication *)application {
    // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later.
    // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
    // Called as part of the transition from the background to the inactive state; here you can undo many of the changes made on entering the background.
}

- (void)applicationDidBecomeActive:(UIApplication *)application {
    // Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
}

- (void)applicationWillTerminate:(UIApplication *)application {
    // Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
}

@end
