package com.alumm0x.scan.http.task.passive;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.ToolsUtil;



public class StaticDownloadApi extends StaticTaskImpl {

    public static String name = "DownloadApi";
    public static String comments = "识别下载场景,可以测试下载相关的问题,如任意下载";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticDownloadApi(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        //识别是否有特征download
        if (this.entity.getCurrent().contains("download")) {
            entity.addTag(this.getClass().getSimpleName());
        }
        // 下载特有的响应头
        String cd = ToolsUtil.hasHeader(BurpReqRespTools.getRespHeaders(entity.getRequestResponse()), "Content-Disposition");
        if (cd != null && cd.contains("attachment")) {
            entity.addTag(this.getClass().getSimpleName());
        }
    }
}

