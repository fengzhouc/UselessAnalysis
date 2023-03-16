package com.alumm0x.scan.http.task.impl;

import com.alumm0x.scan.LogEntry;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.CommonStore;
import com.alumm0x.util.risk.StaticCheckResult;

import java.util.List;
import java.util.Locale;

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

    //检查头部是否包含某信息
    //头部信息包含如下
    //1、请求头/响应头
    //2、首部
    public String check(List<String> headers, String header) {
        if (null == headers) {
            return null;
        }
        for (String s : headers) {
            if (s.toLowerCase(Locale.ROOT).startsWith(header.toLowerCase(Locale.ROOT))) {
                return s;
            }
        }
        return null;
    }
}
