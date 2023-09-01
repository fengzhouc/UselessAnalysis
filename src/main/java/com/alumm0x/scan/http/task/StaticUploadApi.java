package com.alumm0x.scan.http.task;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.ToolsUtil;



public class StaticUploadApi extends StaticTaskImpl {

    public static String name = "UploadApi";
    public static String comments = "识别上传场景";
    public static String fix = "";

    public UselessTreeNodeEntity entity;

    public StaticUploadApi(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        //识别请求头的contentype，文件上传的是multipart/
        String mul = ToolsUtil.hasHdeader(BurpReqRespTools.getRespHeaders(entity.getRequestResponse()), "Content-Type");
        if (mul != null && mul.equalsIgnoreCase("multipart/")) {
            entity.addTag(this.getClass().getSimpleName());
        }
    }
}

