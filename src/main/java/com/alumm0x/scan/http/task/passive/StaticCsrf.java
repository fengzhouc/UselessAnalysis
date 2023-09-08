package com.alumm0x.scan.http.task.passive;

import java.util.ArrayList;
import java.util.List;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.scan.risk.StaticCheckResult;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.ToolsUtil;

import burp.IHttpRequestResponse;



public class StaticCsrf extends StaticTaskImpl {

    public static String name = "Csrf";
    public static String comments = "识别csrf场景,主要是form场景,因为form表单无限制跨域";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticCsrf(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        // -csrf防护
        List<StaticCheckResult> csrf = checkCsrf(entity.getRequestResponse());
        if (csrf != null && csrf.size() > 0){
            entity.addTag(this.getClass().getSimpleName());
            entity.addMap(csrf);
        }
    }

    /**
     * 检查csrf防护
     * @param requestResponse burp请求响应
     * @param reqHeaders_custom 非标请求头列表，包含可能的token
     *
     * 条件：
     * 1.form表单 (默认允许跨域)
     * 2.使用cookie
     * 3.是否有携带token
     */
    public List<StaticCheckResult> checkCsrf(IHttpRequestResponse requestResponse) {
        List<String> reqHeaders = BurpReqRespTools.getReqHeaders(requestResponse);
        byte[] reqBody = BurpReqRespTools.getReqBody(requestResponse);
        //cors会利用浏览器的cookie自动发送机制，如果不是使用cookie做会话管理就没这个问题了
        if (ToolsUtil.hasHeader(reqHeaders, "Cookie") != null) {
            //要包含centen-type,且为form表单
            String ct = ToolsUtil.hasHeader(reqHeaders, "Content-Type");
            if (ct != null && ct.contains("application/x-www-form-urlencoded") && reqBody.length > 0) {
                List<StaticCheckResult> results = new ArrayList<>();
                // 也不包含可能的token，这里就宽泛点，非标请求头为0就存在问题，因为key也不一定带token字样
                if (entity.reqHeaders_custom.size() == 0) {
                    StaticCheckResult result = new StaticCheckResult();
                    result.desc = "FORM表单CSRF风险";
                    result.risk_param = "";
                    result.fix = "建议增加csrf防护机制，如token令牌,form表单默认允许跨域";
                    results.add(result);
                    return results;
                } else {
                    for (String header : entity.reqHeaders_custom.keySet()) {
                        // 没有携带token，常规关键字csrf
                        StaticCheckResult result = new StaticCheckResult();
                        if (!header.toLowerCase().contains("csrf")) {
                            result.desc = "FORM表单CSRF风险";
                        } else {
                            // 带了的需要验证是否正确验证
                            result.desc = "CSRF验证机制，是否真实验证";
                        }
                        result.risk_param = "";
                        result.fix = "建议增加csrf防护机制，如token令牌,form表单默认允许跨域";
                        results.add(result);
                        return results;
                    }
                }
            }
        }
        return null;
    }

}

