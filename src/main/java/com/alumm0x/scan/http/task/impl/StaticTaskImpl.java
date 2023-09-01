package com.alumm0x.scan.http.task.impl;


/**
 * 纯静态检测任务的父类，也就是不需要重放请求的
 */
public abstract class StaticTaskImpl {

    public abstract void run();

}
