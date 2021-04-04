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

#import "ViewController.h"
#include "jailbreak.h"
#include <sys/utsname.h>
#include <time.h>
#include <errno.h>
#include <sys/sysctl.h>

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UIButton *butoon;
@property (weak, nonatomic) IBOutlet UISwitch *tweakswitch;
@property (weak, nonatomic) IBOutlet UILabel *tweaklabel;
@property (weak, nonatomic) IBOutlet UISwitch *sshswitch;
@property (weak, nonatomic) IBOutlet UILabel *sshlabel;
@property (weak, nonatomic) IBOutlet UISwitch *jailbreakswitch;
@property (weak, nonatomic) IBOutlet UILabel *jailbreaklabel;

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

- (void)tweakChanged:(id)sender {
    BOOL tweaksEnabled = [sender isOn];
    [[NSUserDefaults standardUserDefaults] setBool:tweaksEnabled forKey:@"tweaksEnabled"];
}

- (void)sshChanged:(id)sender {
    BOOL sshEnabled = [sender isOn];
    [[NSUserDefaults standardUserDefaults] setBool:sshEnabled forKey:@"sshEnabled"];
}

- (void)jailbreakChanged:(id)sender {
    BOOL jailbreakEnabled = [sender isOn];
    [[NSUserDefaults standardUserDefaults] setBool:jailbreakEnabled forKey:@"jailbreakEnabled"];
}



- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    if (
        [[NSFileManager defaultManager]fileExistsAtPath:@"/Applications/Cydia.app/"]) {
        _butoon.enabled = false;
        _butoon.hidden  = true;
        
        if ([[NSUserDefaults standardUserDefaults] boolForKey:@"notfirst"]) {
            [_tweakswitch setOn:([[NSUserDefaults standardUserDefaults] boolForKey:@"tweaksEnabled"])];
            [_sshswitch setOn:([[NSUserDefaults standardUserDefaults] boolForKey:@"sshEnabled"])];
            [_jailbreakswitch setOn:([[NSUserDefaults standardUserDefaults] boolForKey:@"jailbreakEnabled"])];
        }
        else {
            UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"README"
                                                            message:@"The jailbreak switch is currently disabled due to a bug, therefore it is stuck in the on position for the time being."
                                                           delegate:self
                                                  cancelButtonTitle:@"OK"
                                                  otherButtonTitles:nil];
            [alert show];
        }
         
        
        _tweakswitch.hidden = false;
        _tweaklabel.hidden = false;
        _sshswitch.hidden = false;
        _sshlabel.hidden = false;
        _jailbreakswitch.hidden = false;
        _jailbreaklabel.hidden = false;
        
        [_tweakswitch addTarget:self action:@selector(tweakChanged:) forControlEvents:UIControlEventValueChanged];
        [_sshswitch addTarget:self action:@selector(sshChanged:) forControlEvents:UIControlEventValueChanged];
        [_jailbreakswitch addTarget:self action:@selector(jailbreakChanged:) forControlEvents:UIControlEventValueChanged];
        
        
        [_butoon setTitle:@"jailbroken" forState:UIControlStateNormal];
        [[NSUserDefaults standardUserDefaults] setBool:true forKey:@"notfirst"];
        
    }
    /* now unnecessary */
    //[[UIApplication sharedApplication] registerUserNotificationSettings:[UIUserNotificationSettings settingsForTypes:(UIUserNotificationTypeSound | UIUserNotificationTypeAlert | UIUserNotificationTypeBadge) categories:nil]];
    [[UIApplication sharedApplication] registerForRemoteNotifications];
    NSLog(@"viewDidLoad executed");
    //viewDidExecute = 1;
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
