//
//  ViewController.m
//  Athenus
//

#import "ViewController.h"
#include "jailbreak.h"
#include <sys/utsname.h>
#include <time.h>
#include <errno.h>
#include <sys/sysctl.h>

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UIButton *butoon;

@end

@implementation ViewController

extern int viewDidExecute;
- (IBAction)jelbrek:(id)sender {
    struct utsname name;
    uname(&name);
    if (!strstr(name.version, "MarijuanARM")){
        usleep(USEC_PER_SEC/100);
        
        dispatch_async(jailbreak_queue , ^{
            jailbreak();
        });
    }
}

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    if (
        [[NSFileManager defaultManager]fileExistsAtPath:@"/Applications/Cydia.app/"]) {
        _butoon.hidden = true;
        _butoon.enabled = false;
        
    }
    [[UIApplication sharedApplication] registerUserNotificationSettings:[UIUserNotificationSettings settingsForTypes:(UIUserNotificationTypeSound | UIUserNotificationTypeAlert | UIUserNotificationTypeBadge) categories:nil]];
    [[UIApplication sharedApplication] registerForRemoteNotifications];
    NSLog(@"viewDidLoad executed");
    //viewDidExecute = 1;
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
