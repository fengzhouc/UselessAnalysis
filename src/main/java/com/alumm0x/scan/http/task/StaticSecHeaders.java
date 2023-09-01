package com.alumm0x.scan.http.task;

import java.util.ArrayList;
import java.util.List;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.scan.risk.StaticCheckResult;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.ToolsUtil;

import burp.IHttpRequestResponse;



public class StaticSecHeaders extends StaticTaskImpl {

    public static String name = "SecHeaders";
    public static String comments = "识别安全响应头是否配置";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticSecHeaders(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        // -安全响应头配置（太多了，基本都有，低危先忽略吧）
        List<StaticCheckResult> unsafe = checkSecHeader(entity.getRequestResponse());
        if (unsafe != null && unsafe.size() > 0){
            entity.addTag(this.getClass().getSimpleName());
            entity.addMap(unsafe);
        }
    }

    /**
     * 检查安全响应头配置
     * @param requestResponse burp请求响应
     */
    public  List<StaticCheckResult> checkSecHeader(IHttpRequestResponse requestResponse) {
        List<String> respHeaders = BurpReqRespTools.getRespHeaders(requestResponse);
        List<StaticCheckResult> results = new ArrayList<>();
        if (ToolsUtil.hasHdeader(respHeaders, "x-xss-protection") == null) {
            StaticCheckResult result = new StaticCheckResult();
            result.desc = "未开启X-XSS-Protection";
            result.risk_param = "";
            result.fix = "建议开启，纵深防御，客户端防护XSS。推荐配置 1;mode=block";
            results.add(result);
        }
        if (ToolsUtil.hasHdeader(respHeaders, "x-frame-options") == null) {
            StaticCheckResult result = new StaticCheckResult();
            result.desc = "未开启X-Frame-Options";
            result.risk_param = "";
            result.fix = "建议开启，纵深防御，客户端防护XSS。推荐配置 SAMEORIGIN";
            results.add(result);
        }
        if (ToolsUtil.hasHdeader(respHeaders, "x-content-type-options") == null) {
            StaticCheckResult result = new StaticCheckResult();
            result.desc = "未开启X-Content-Type-Options";
            result.risk_param = "";
            result.fix = "建议开启，纵深防御，客户端防护XSS。推荐配置 nosniff";
            results.add(result);
        }
        // HSTS这个支持不多，就不检测了
        // if (check(respHeaders, "http-strict-transport-security") != null) {}
        return results;
    }
}

