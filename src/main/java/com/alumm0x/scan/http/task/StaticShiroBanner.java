package com.alumm0x.scan.http.task;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.ToolsUtil;



public class StaticShiroBanner extends StaticTaskImpl {

    public static String name = "ShiroBanner";
    public static String comments = "识别是否使用shiro框架的信息";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticShiroBanner(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        // 检测shiro的指纹
        String setCookie = ToolsUtil.hasHdeader(BurpReqRespTools.getRespHeaders(entity.getRequestResponse()), "Set-Cookie");
        if (setCookie != null && setCookie.toLowerCase().contains("rememberme=")) {
            entity.addTag(this.getClass().getSimpleName());
        }
    }
}

