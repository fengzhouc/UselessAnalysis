package com.alumm0x.scan.http.task;

import java.util.ArrayList;
import java.util.List;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.scan.risk.StaticCheckResult;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;

import burp.IHttpRequestResponse;



public class StaticUnsfeDesignLogin extends StaticTaskImpl {

    public static String name = "UnsfeDesignLogin";
    public static String comments = "识别不安全设计之登录相关设计";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticUnsfeDesignLogin(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        List<StaticCheckResult> unsafe = checkUnsfeDesignLogin(entity.getRequestResponse());
        if (unsafe != null && unsafe.size() > 0){
            entity.addTag(this.getClass().getSimpleName());
            entity.addMap(unsafe);
        }
    }

    /**
     * 检查不安全设计-login使用get请求
     * @param requestResponse burp请求响应
     */
    public List<StaticCheckResult> checkUnsfeDesignLogin(IHttpRequestResponse requestResponse) {
        if (StaticLoginApi.isLoginApi(requestResponse)) {
            List<StaticCheckResult> results = new ArrayList<>();
            // 登录登出使用GET请求
            if (BurpReqRespTools.getMethod(requestResponse).equalsIgnoreCase("GET")) {
                    StaticCheckResult result = new StaticCheckResult();
                    result.desc = "不安全设计-login使用GET方法";
                    result.risk_param = "";
                    result.fix = "登录登出禁止使用GET请求方式,自行判断是否是页面,而非接口请求; 可能会存在CSRF攻击的风险";
                    results.add(result);
            }
            // url中传递账号密码
            if (BurpReqRespTools.getQuery(requestResponse) != null && (
                        BurpReqRespTools.getQuery(requestResponse).contains("username")
                        || BurpReqRespTools.getQuery(requestResponse).contains("password")
                )) {
                StaticCheckResult result = new StaticCheckResult();
                result.desc = "不安全设计-login使用query传递账号密码";
                result.risk_param = "";
                result.fix = "账号密码等敏感信息禁止url中传递";
                results.add(result);
            }
            return results;
        }
        return null;
    }
}

