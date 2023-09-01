package com.alumm0x.scan.http.task;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.scan.risk.StaticCheckResult;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;

import burp.IHttpRequestResponse;



public class StaticSsrf extends StaticTaskImpl {

    public static String name = "Ssrf";
    public static String comments = "识别Ssrf场景";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticSsrf(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        // -ssrf（请求和响应中是否有url的数据）
        List<StaticCheckResult> ssrf = checkSsrf(entity.getRequestResponse());
        if (ssrf != null && ssrf.size() > 0){
            entity.addTag(this.getClass().getSimpleName());
            entity.addMap(ssrf);
        }
    }

    /**
     * 检查ssrf,在参数中是否有url
     * @param requestResponse burp请求响应
     */
    public List<StaticCheckResult> checkSsrf(IHttpRequestResponse requestResponse) {
        Map<String, Object> querys = BurpReqRespTools.getQueryMap(requestResponse);
        byte[] reqBody = BurpReqRespTools.getReqBody(requestResponse);
        // ssrf就是需要传入完整的url，所以正则匹配请求参数
        String regex = "http[s]?://(.*?)[/&\"]+?[\\w/\\-\\._]*";
        List<StaticCheckResult> results = new ArrayList<>();
        //如果有body参数，需要多body参数进行测试
        if (reqBody.length > 0){
            String request_body_str = new String(reqBody);
            //检测是否存在url地址的参数，正则匹配
            Pattern pattern = Pattern.compile(regex);
            Matcher matcher = pattern.matcher(request_body_str);
            if (matcher.find()){//没匹配到则不进行后续验证
                StaticCheckResult result = new StaticCheckResult();
                result.desc = "SSRF风险";
                result.risk_param = matcher.group(0);
                result.fix = "建议服务器端限制url的域名，设置白名单。";
                results.add(result);
                return results;
            }
        } else if (querys.size() > 0){
            //检测是否存在url地址的参数，正则匹配
            Pattern pattern = Pattern.compile(regex);
            Matcher matcher = pattern.matcher(querys.toString());
            if (matcher.find()){//没匹配到则不进行后续验证
                StaticCheckResult result = new StaticCheckResult();
                result.desc = "SSRF风险";
                result.risk_param = matcher.group(0);
                result.fix = "建议服务器端限制重定向的域名，设置白名单。";
                results.add(result);
                return results;
            }
        }
        return null;
    }
}

