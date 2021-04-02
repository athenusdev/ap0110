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

#import <UIKit/UIKit.h>
#import "AppDelegate.h"
#include <dlfcn.h>

int main(int argc, char * argv[]) {
//    dsystem = dlsym(RTLD_DEFAULT,"system");
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class])); // important!!!
    }
}
