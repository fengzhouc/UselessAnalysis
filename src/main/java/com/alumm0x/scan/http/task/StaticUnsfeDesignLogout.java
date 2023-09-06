package com.alumm0x.scan.http.task;

import java.util.ArrayList;
import java.util.List;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.scan.risk.StaticCheckResult;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;

import burp.IHttpRequestResponse;



public class StaticUnsfeDesignLogout extends StaticTaskImpl {

    public static String name = "UnsfeDesignLogout";
    public static String comments = "识别不安全设计之登出相关设计";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticUnsfeDesignLogout(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        // -设计不合理的，如logout使用get
        List<StaticCheckResult> unsafe = checkUnsfeDesignLogout(entity.getRequestResponse());
        if (unsafe != null && unsafe.size() > 0){
            entity.addTag(this.getClass().getSimpleName());
            entity.addMap(unsafe);
        }
    }

    /**
     * 检查不安全设计-logout使用get请求
     * @param requestResponse burp请求响应
     */
    public List<StaticCheckResult> checkUnsfeDesignLogout(IHttpRequestResponse requestResponse) {
        if (StaticLogoutApi.isLogoutApi(requestResponse)) {
            List<StaticCheckResult> results = new ArrayList<>();
            // 登出使用GET请求
            if (BurpReqRespTools.getMethod(requestResponse).equalsIgnoreCase("GET")) {
                    StaticCheckResult result = new StaticCheckResult();
                    result.desc = "不安全设计-logout使用GET方法";
                    result.risk_param = "";
                    result.fix = "登出禁止使用GET请求方式,自行判断是否是页面,而非接口请求; 接口的话可能会存在CSRF攻击的风险,造成恶意登出,导致用户体验降低";
                    results.add(result);
            }
            return results;
        }
        return null;
    }
}

