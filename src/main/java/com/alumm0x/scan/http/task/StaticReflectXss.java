package com.alumm0x.scan.http.task;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.scan.risk.StaticCheckResult;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.ToolsUtil;

import burp.IHttpRequestResponse;



public class StaticReflectXss extends StaticTaskImpl {

    public static String name = "ReflectXss";
    public static String comments = "识别反射性XSS场景,检测响应体中是否包含参数";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticReflectXss(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        // 反射型xss的静态检测
        List<StaticCheckResult> xss = checkReflectXss(entity.getRequestResponse());
        if (xss != null && xss.size() > 0){
            entity.addTag(this.getClass().getSimpleName());
            entity.addMap(xss);
        }
    }

    /**
     * 检查反射型XSS
     * @param requestResponse burp请求响应
     */
    public static List<StaticCheckResult> checkReflectXss(IHttpRequestResponse requestResponse) {
        // 获取相应的content-type
        String resp_ct = ToolsUtil.hasHeader(BurpReqRespTools.getRespHeaders(requestResponse), "content-type");
        if (resp_ct != null 
            && (resp_ct.contains("html") 
                || resp_ct.contains("javascript")) // 有些模版js可能会有，后缀为js的不太会
            && BurpReqRespTools.getRespBody(requestResponse).length > 0) {
            List<StaticCheckResult> results = new ArrayList<>();
            String respbody = new String(BurpReqRespTools.getRespBody(requestResponse));
            // 检查查询参数是否有在响应中
            if (BurpReqRespTools.getQuery(requestResponse) != null) {
                for (Map.Entry<String, Object> entry :
                        BurpReqRespTools.getQueryMap(requestResponse).entrySet()) {
                    // TODO 这种方式误报比较多，有待提升
                    if (respbody.contains((String) entry.getValue())) {
                        StaticCheckResult result = new StaticCheckResult();
                        result.desc = "反射型XSS-" + entry.getKey();
                        result.risk_param = entry.getKey();
                        result.fix = "根据数据输出的位置进行输出编码。可用业内成熟框架: esapi";
                        results.add(result);
                    }
                }

            }
            // 检查请求体的参数是否在响应中
            // TODO 响应体参数目前还没有解析成健值对

            return results;
        }
        return null;
    }
}

