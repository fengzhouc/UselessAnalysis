package com.alumm0x.scan.http.task;

import java.util.ArrayList;
import java.util.List;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.scan.risk.StaticCheckResult;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;

import burp.IHttpRequestResponse;



public class StaticUnsfeDesignContentType extends StaticTaskImpl {

    public static String name = "UnsfeDesignContentType";
    public static String comments = "识别不安全设计之数据与ContentType不匹配";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticUnsfeDesignContentType(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        // -设计不合理的，如contenttype不符合数据
        List<StaticCheckResult> unsafe_ct = checkUnsfeDesignContentType(entity.tabs, entity.getRequestResponse());
        if (unsafe_ct != null && unsafe_ct.size() > 0){
            entity.addTag(this.getClass().getSimpleName());
            entity.addMap(unsafe_ct);
        }
    }

    /**
     * 检查不安全设计-content-type与实际数据不符
     * @param tabs 标签列表
     * @param requestResponse burp请求响应
     */
    public static List<StaticCheckResult> checkUnsfeDesignContentType(List<String> tabs, IHttpRequestResponse requestResponse) {
        if (tabs.contains("json")) {
            if (!BurpReqRespTools.getContentType(requestResponse).contains("json")) {
                List<StaticCheckResult> results = new ArrayList<>();
                StaticCheckResult result = new StaticCheckResult();
                result.desc = "不安全设计-Content-Type不符合数据结构";
                result.risk_param = "";
                result.fix = "请求的Content-type必须与数据结构匹配,且服务端必须要限制";
                results.add(result);
                return results;
            }
        }
        return null;
    }
}

