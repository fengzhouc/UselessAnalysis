package com.alumm0x.scan.http.task.impl;

import com.alumm0x.scan.LogEntry;
import com.alumm0x.scan.risk.StaticCheckResult;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.CommonStore;

/**
 * 纯静态检测任务的父类，也就是不需要重放请求的
 */
public abstract class StaticTaskImpl {

    public abstract void run();

}
