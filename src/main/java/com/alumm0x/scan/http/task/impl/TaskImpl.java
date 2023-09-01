package com.alumm0x.scan.http.task.impl;

import com.alumm0x.scan.LogEntry;
import com.alumm0x.scan.risk.StaticCheckResult;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.CommonStore;

/**
 * 动态检测任务的父类，也就是需要重放请求的
 */
public abstract class TaskImpl {

    public abstract void run();

    // 添加待检测的task
    // 添加synchronized防止多线程竞态
    public synchronized LogEntry logAddToScanLogger(String url,String poc) {
        int row = CommonStore.log.size();
        LogEntry logEntry = new LogEntry(row,null, url,poc);
        CommonStore.log.add(logEntry);
        // 刷新表格数据模型
        CommonStore.logModel.update();
        return logEntry;
    }

    // 添加待检测的task
    // 添加synchronized防止多线程竞态
    public synchronized StaticCheckResult logAddToPocs(UselessTreeNodeEntity entity, String name , String comments, String fix) {
        StaticCheckResult poc = new StaticCheckResult();
        poc.desc = name;
        poc.risk_param = comments;
        poc.fix = fix;
        entity.pocs.put(poc.desc,poc);
        // 刷新表格数据模型
        CommonStore.POC_TABLEMODEL.fireTableDataChanged();
        return poc;
    }

}
