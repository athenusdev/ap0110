//
//  main.m
//  Athenus
//

#import <UIKit/UIKit.h>
#import "AppDelegate.h"
#include <dlfcn.h>

int main(int argc, char * argv[]) {
//    dsystem = dlsym(RTLD_DEFAULT,"system");
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class])); // important!!!
    }
}
