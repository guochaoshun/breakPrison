//
//  BreakPrison.m
//  越狱
//
//  Created by apple on 2019/4/23.
//  Copyright © 2019 apple. All rights reserved.
//

#import "BreakPrison.h"
#import <UIKit/UIKit.h>
#import <sys/stat.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>


@implementation BreakPrison

// 参考代码 : https://www.jianshu.com/p/a43be50dc958
// https://github.com/guochaoshun/breakPrison
// load是系统调用的,不会被hook,一定要用真机测试
+ (void)load {
    
    if (isAlreadyBreakPrison()) {
        NSLog(@"该设备已经越狱了");
//        exit(0);
    }
    NSLog(@"设备正常");

}

//为什么用c方法呢?
//因为c语言是静态的,在编译时已经确定了,不会被hook,而系统的c方法,因为动态链接库的原因,可能被hook
/// 这个设备是否已经越狱了,
bool isAlreadyBreakPrison(){
    
    // 1.越狱后会在系统的根目录下添加一些文件,根据这些文件是否存在,判定是否越狱

    // Cydia是越狱过程中装的一个破解软件,类似于App Store
    NSString *cydiaPath = @"/Applications/Cydia.app";
    NSString *aptPath = @"/private/var/lib/apt/";
    // 未越狱的手机没有权限查看系统的按照目录,可以通过尝试读取应用列表，看有无权限：
    NSString *applications = @"/User/Applications/";
    // dylib动态库注入也是常有的攻击手段
    NSString *Mobile = @"/Library/MobileSubstrate/MobileSubstrate.dylib";
    // 这个是脚本(Unix shell),正常iOS是没有的
    NSString *bash = @"/bin/bash";
    // linux下控制脚本的
    NSString *sshd =@"/usr/sbin/sshd";
    NSString *sd = @"/etc/apt";
    
    NSArray * fileArray = @[cydiaPath,aptPath,applications,
                            Mobile,bash,sshd,sd];
    for (NSString * filePath in fileArray) {
        
        if([[NSFileManager defaultManager] fileExistsAtPath:filePath]) {
            return YES;
        }
        
    }
    
    
    //2.使用stat系列函数检测Cydia等工具
    // stat函数: 通过文件名filename获取文件信息，并保存在buf所指的结构体stat中
    // 执行成功则返回0，失败返回-1
    struct stat stat_info;
    if (0 == stat("/Applications/Cydia.app", &stat_info)) {
        return YES;
    }
    if([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://"]]){
        return YES;
    }
    
    
    //3.检查下stat是否被替换
    // stat函数可以被fishhook替换掉,
    // 看看stat是不是出自系统库，有没有被攻击者换掉
    // 如果结果不是 /usr/lib/system/libsystem_kernel.dylib 的话，那就100%被攻击了。
    int ret;
    Dl_info dylib_info;
    int (*func_stat)(const char *, struct stat *) = stat;
    // dladdr : 获取某个地址的符号信息
    if ((ret = dladdr(func_stat, &dylib_info))) {
        NSString *str = [NSString stringWithFormat:@"%s",dylib_info.dli_fname];
        if (![str isEqualToString:@"/usr/lib/system/libsystem_kernel.dylib"]) {
            return YES;
        }
        
    }
    
    
    
    
    
    //4.MobileSubstrate.dylib是一个动态库框架，允许第三方的开发者在系统的方法里打一些运行时补丁
    // https://blog.csdn.net/king_jensen/article/details/30746765
    // 越狱机的输出结果会包含字符串： Library/MobileSubstrate/MobileSubstrate.dylib 。
    
    // 获取到所有的动态模块
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0 ; i < count; ++i) {
        
        NSString *name = [[NSString alloc]initWithUTF8String:_dyld_get_image_name(i)];
        //        NSLog(@"%@",name);
        if ([name containsString:@"Library/MobileSubstrate/MobileSubstrate.dylib"]) {
            return YES;
        }
        
    }
    
    
    
    //5.DYLD_INSERT_LIBRARIES环境变量，可以不修改App的任何字节，实现注入dyld的过程。
    // getenv:从环境中取字符串,获取环境变量的值.
    // 未越狱设备返回结果是null，越狱设备就各有各的精彩了，尤其是老一点的iOS版本越狱环境。
    char *env = getenv("DYLD_INSERT_LIBRARIES");
    if(env){
        return YES;
    }
    
    
    
    return NO;
}











@end
