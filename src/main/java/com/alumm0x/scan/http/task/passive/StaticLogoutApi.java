package com.alumm0x.scan.http.task.passive;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.ToolsUtil;

import burp.IHttpRequestResponse;



public class StaticLogoutApi extends StaticTaskImpl {

    public static String name = "LogoutApi";
    public static String comments = "识别登出的接口";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticLogoutApi(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        if (isLogoutApi(entity.getRequestResponse())) {
            entity.addTag(this.getClass().getSimpleName());
        }
    }

    /**
     * 判断该该请求是否为登录登出接口
     * @param requestResponse
     * @return
     */
    public static boolean isLogoutApi(IHttpRequestResponse requestResponse) {
        //1.识别url特征，如logout
        String url = BurpReqRespTools.getUrl(requestResponse);
        if (url.contains("logout")) {
            return true;
        }
        //2.识别响应头Set-Cookie，一般是登录登出的时候会有这类操作，当然排除不使用cookie作会话凭证的 (这只是遇到的某一种设计，登出后会置空客户端的cookie)
        String setCookie = ToolsUtil.hasHeader(BurpReqRespTools.getRespHeaders(requestResponse), "Set-Cookie");
        if (setCookie != null && (setCookie.contains("=\"\"") || setCookie.contains("=;"))) {
            return true;
        }
        return false;
    }
}

