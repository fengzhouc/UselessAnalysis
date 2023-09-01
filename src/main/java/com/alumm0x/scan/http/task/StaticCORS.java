package com.alumm0x.scan.http.task;

import java.util.ArrayList;
import java.util.List;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.scan.risk.StaticCheckResult;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.ToolsUtil;

import burp.IHttpRequestResponse;



public class StaticCORS extends StaticTaskImpl {

    public static String name = "CORS";
    public static String comments = "检查跨域策略,是否存在无限制跨域的风险";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticCORS(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        // -CORS配置
        List<StaticCheckResult> cors = checkCors(entity.getRequestResponse());
        if (cors != null && cors.size() > 0){
            entity.addTag(this.getClass().getSimpleName());
            entity.addMap(cors);
        }
    }

    /**
     * 检查CORS跨域配置
     * @param requestResponse burp请求响应
     */
    public static List<StaticCheckResult> checkCors(IHttpRequestResponse requestResponse) {
        List<String> reqHeaders = BurpReqRespTools.getReqHeaders(requestResponse);
        List<String> respHeaders = BurpReqRespTools.getRespHeaders(requestResponse);
        //cors会利用浏览器的cookie自动发送机制，如果不是使用cookie做会话管理就没这个问题了
        if (ToolsUtil.hasHdeader(reqHeaders, "Cookie") != null){
            List<StaticCheckResult> results = new ArrayList<>();
            /*
             * ajax请求跨域获取数据的条件
             * 1、Access-Control-Allow-Credentials为true
             * 2、Access-Control-Allow-Origin为*或者根据origin动态设置
             */
            if (ToolsUtil.hasHdeader(respHeaders, "Access-Control-Allow-Origin") != null){
                String origin_resp = ToolsUtil.hasHdeader(respHeaders, "Access-Control-Allow-Origin");
                String credentials = ToolsUtil.hasHdeader(respHeaders, "Access-Control-Allow-Credentials");
                if (credentials != null && credentials.contains("true")){
                    if (origin_resp.contains("*")) {
                        // 配置为*则允许任意跨域请求，存在风险
                        StaticCheckResult result = new StaticCheckResult();
                        result.desc = "任意跨域风险";
                        result.risk_param = origin_resp;
                        result.fix = "如需要跨域请求，则不要配置为* ，需根据业务场景，精确限制跨域范围；如不需要跨域，则Access-Control-Allow-Credentials配置为false。";
                        results.add(result);
                    }else {
                        String origin_req = ToolsUtil.hasHdeader(reqHeaders, "Origin");
                        // 请求头中存在Orgin，且origin的值相同
                        if (origin_req != null && origin_req.split(":", 2)[1].trim().equalsIgnoreCase(origin_resp.split(":", 2)[1].trim())) {
                            // 检查下是否为Origin请求头的值，如果是，则需要验证下是否动态设置，动态设置相当于允许任意跨域
                            StaticCheckResult result = new StaticCheckResult();
                            result.desc = "动态CORS风险";
                            result.risk_param = origin_req;
                            result.fix = "如需要跨域请求,需限制域名范围，如xxx.com主域名";
                            results.add(result);
                        }
                    }
                }
            }
            return results;
        }
        return null;
    }
}

