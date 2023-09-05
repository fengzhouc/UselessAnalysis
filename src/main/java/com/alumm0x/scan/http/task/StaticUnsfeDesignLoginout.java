package com.alumm0x.scan.http.task;

import java.util.ArrayList;
import java.util.List;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.scan.risk.StaticCheckResult;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.ToolsUtil;

import burp.IHttpRequestResponse;



public class StaticUnsfeDesignLoginout extends StaticTaskImpl {

    public static String name = "UnsfeDesignLoginout";
    public static String comments = "识别不安全设计之登录登出使用GET请求";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticUnsfeDesignLoginout(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        // -设计不合理的，如logout使用get
        List<StaticCheckResult> unsafe = checkUnsfeDesignLoginout(entity.getRequestResponse());
        if (unsafe != null && unsafe.size() > 0){
            entity.addTag(this.getClass().getSimpleName());
            entity.addMap(unsafe);
        }
    }

    /**
     * 检查不安全设计-login/out使用get请求
     * @param tabs 标签列表
     * @param requestResponse burp请求响应
     */
    public List<StaticCheckResult> checkUnsfeDesignLoginout(IHttpRequestResponse requestResponse) {
        if (StaticLoginOutApi.isLoginOutApi(requestResponse)) {
            List<StaticCheckResult> results = new ArrayList<>();
            // 登录登出使用GET请求,排除掉响应是html的，这个一般是登录页面
            if (BurpReqRespTools.getMethod(requestResponse).equalsIgnoreCase("GET")) {
                    StaticCheckResult result = new StaticCheckResult();
                    result.desc = "不安全设计-login/out使用GET方法";
                    result.risk_param = "";
                    result.fix = "登录登出禁止使用GET请求方式,自行判断是否是页面,而非接口请求";
                    results.add(result);
            }
            // url中传递账号密码
            if (BurpReqRespTools.getQuery(requestResponse) != null && (
                        BurpReqRespTools.getQuery(requestResponse).contains("username")
                        || BurpReqRespTools.getQuery(requestResponse).contains("password")
                )) {
                StaticCheckResult result = new StaticCheckResult();
                result.desc = "不安全设计-login/out使用query传递账号密码";
                result.risk_param = "";
                result.fix = "账号密码等敏感信息禁止url中传递";
                results.add(result);
            }
            return results;
        }
        return null;
    }
}

