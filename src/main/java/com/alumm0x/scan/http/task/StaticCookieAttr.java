package com.alumm0x.scan.http.task;

import java.util.ArrayList;
import java.util.List;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.scan.risk.StaticCheckResult;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.ToolsUtil;

import burp.IHttpRequestResponse;



public class StaticCookieAttr extends StaticTaskImpl {

    public static String name = "CookieAttr";
    public static String comments = "检查cookie的安全属性是否添加";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticCookieAttr(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        List<StaticCheckResult> unsafe = hasAttr(entity.getRequestResponse());
        if (unsafe != null && unsafe.size() > 0) {
            entity.addTag(this.getClass().getSimpleName());
            entity.addMap(unsafe);
        }
    }

    /**
     * 判断set-cookie是否包含安全属性
     * @param requestResponse
     * @return
     */
    public static List<StaticCheckResult> hasAttr(IHttpRequestResponse requestResponse) {
        //识别响应头Set-Cookie，是否包含httponly、secure
        String setCookie = ToolsUtil.hasHeader(BurpReqRespTools.getRespHeaders(requestResponse), "Set-Cookie");
        if (setCookie != null) {
            List<StaticCheckResult> results = new ArrayList<>();
            for ( String header : BurpReqRespTools.getRespHeaders(requestResponse)) {
                if (header.trim().toLowerCase().startsWith("set-cookie")){
                    if (!header.toLowerCase().contains("httponly")) {
                        StaticCheckResult result = new StaticCheckResult();
                        result.desc = "cookie未添加httponly";
                        result.risk_param = header;
                        result.fix = "敏感cookie必须要添加httponly";
                        results.add(result);
                    }
                    if (!header.toLowerCase().contains("secure")){
                        StaticCheckResult result = new StaticCheckResult();
                        result.desc = "cookie未添加secure";
                        result.risk_param = header;
                        result.fix = "敏感cookie必须要添加secure";
                        results.add(result);
                    }
                }
            }
            return results;
        }
        return null;
    }
}

