package com.alumm0x.scan.http.task;

import java.util.ArrayList;
import java.util.List;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.scan.risk.StaticCheckResult;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.ToolsUtil;
import com.alumm0x.util.param.json.JsonTools;

import burp.IHttpRequestResponse;



public class StaticJsonCsrf extends StaticTaskImpl {

    public static String name = "JsonCsrf";
    public static String comments = "识别JsonCsrf场景,请求体是json数据,且使用Cookie";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticJsonCsrf(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        // -jsoncsrf防护
        List<StaticCheckResult> jsrf = checkJsonCsrf(entity.getRequestResponse());
        if (jsrf != null && jsrf.size() > 0){
            entity.addTag(this.getClass().getSimpleName());
            entity.addMap(jsrf);
        }
    }

    /**
     * 检查Jsoncsrf防护
     * @param tabs 标签列表
     * @param requestResponse burp请求响应
     *
     * 条件：其实就是因为服务端没有限制centen-type，所以请求专程form提交
     * 1.json数据
     * 2.使用cookie
     * 3.后端没有限制content-type（这个是需要后续验证，满足上面三条就报问题了）
     */
    public static List<StaticCheckResult> checkJsonCsrf(IHttpRequestResponse requestResponse) {
        List<String> reqHeaders = BurpReqRespTools.getReqHeaders(requestResponse);
        byte[] reqBody = BurpReqRespTools.getReqBody(requestResponse);
        if ((JsonTools.isJsonObj(new String(BurpReqRespTools.getReqBody(requestResponse))) || JsonTools.isJsonArr(new String(BurpReqRespTools.getReqBody(requestResponse)))) && ToolsUtil.hasHeader(reqHeaders, "Cookie") != null && reqBody.length > 0) {
                List<StaticCheckResult> results = new ArrayList<>();
                StaticCheckResult result = new StaticCheckResult();
                result.desc = "JsonCsrf风险";
                result.risk_param = "";
                result.fix = "修改为form的contenttype重放请求，修复建议: 后端接口限制contentType";
                results.add(result);
                return results;
        }
        return null;
    }
}

