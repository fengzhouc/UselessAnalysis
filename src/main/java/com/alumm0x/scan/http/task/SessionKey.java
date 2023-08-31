package com.alumm0x.scan.http.task;

import com.alumm0x.scan.LogEntry;
import com.alumm0x.scan.http.task.impl.TaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;


public class SessionKey extends TaskImpl {

    public static String name = "SessionKey";
    public static String comments = "微信SessionKey泄漏，会造成任意用户登陆";
    public static String fix = "禁止返回SessionKey到客户端，造成泄漏风险，";

    public UselessTreeNodeEntity entity;

    public SessionKey(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        LogEntry logEntry = logAddToScanLogger(entity.getCurrent(), "SessionKey");
        logEntry.requestResponse = entity.getRequestResponse();
        // 检查响应中是否包含sessionkek关键字
        String body = new String(BurpReqRespTools.getRespBody(entity.getRequestResponse()));
        if (body.toLowerCase().contains("sessionkey") || body.toLowerCase().contains("session_key") || body.toLowerCase().contains("session-key")) {
            logEntry.hasVuln();
            logEntry.Comments = new String(SessionKey.comments);
        }
        // 检查结束后查看是否存在漏洞，不存在则修改状态为Done
        if (!logEntry.isVuln()) {
            logEntry.onResponse();
        } else {
            entity.color = "red";
        }
    }
}

