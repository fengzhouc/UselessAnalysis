package com.alumm0x.scan.http.task.passive;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.scan.risk.StaticCheckResult;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonStore;

import burp.IHttpRequestResponse;



public class StaticRedirect extends StaticTaskImpl {

    public static String name = "Redirect";
    public static String comments = "识别重定向的场景场景";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticRedirect(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        // -重定向
        List<StaticCheckResult> rs = checkRedirect(entity.getRequestResponse());
        if (rs != null && rs.size() > 0){
            entity.addTag(this.getClass().getSimpleName());
            entity.addMap(rs);
        }
    }

    /**
     * 检查重定向风险
     * @param requestResponse burp请求响应
     */
    public static List<StaticCheckResult> checkRedirect(IHttpRequestResponse requestResponse) {
        Map<String, Object> querys = BurpReqRespTools.getQueryMap(requestResponse);
        //2.请求的url中含redirect敏感参数
        for (String query : querys.keySet()) {
            if (CommonStore.REDIRECT_SCOPE.contains(query)) {
                Object value = querys.get(query);
                List<StaticCheckResult> results = new ArrayList<>();
                StaticCheckResult result = new StaticCheckResult();
                result.desc = "任意重定向风险";
                result.risk_param = query + "=" + value;
                result.fix = "建议服务器端限制重定向的域名，设置白名单。";
                results.add(result);
                return results;
            }
        }
        return null;
    }
}

