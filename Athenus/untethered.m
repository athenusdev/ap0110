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
 *         - python 0dayz thnx
 */

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
   system("/deepseawood");
}

int fun(int argc, char* argv[]) {
    
    // new untether 0day - spv
    
    jelbrekme();
    
    system("multi_kloader /iBSS /iBEC");
    
    printf("pwned iphone\n");
  
   
    return 0;
}
