//
//  jailbreak.h
//  doubleH3lix
//
//  Created by tihmstar on 18.02.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#ifndef jailbreak_h
#define jailbreak_h

#include <dispatch/dispatch.h>

extern dispatch_queue_t jailbreak_queue;

int jailbreak(void);

int jailbreak_system(const char *command);

#endif /* jailbreak_h */
