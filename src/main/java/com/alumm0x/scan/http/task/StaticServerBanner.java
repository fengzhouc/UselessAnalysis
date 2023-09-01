package com.alumm0x.scan.http.task;

import java.util.List;

import com.alumm0x.scan.http.task.impl.StaticTaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.SourceLoader;
import com.alumm0x.util.ToolsUtil;

import burp.IRequestInfo;


public class StaticServerBanner extends StaticTaskImpl {

    public static String name = "ServerBanner";
    public static String comments = "使用系统指纹,包含Server响应头、Url、Body等关键词的匹配";
    public static String fix = "建议隐藏真实服务器信息,如版本号";

    public UselessTreeNodeEntity entity;

    public StaticServerBanner(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        IRequestInfo requestInfo = BurpReqRespTools.getRequestInfo(entity.getRequestResponse());
        // Server指纹
        String server = ToolsUtil.hasHdeader(BurpReqRespTools.getReqHeaders(entity.getRequestResponse()), "Server");
        if (server != null) {
            entity.addTag(server);
        }
        // 匹配url，收集一份url
        String path = requestInfo.getUrl().getPath();
        List<String> banners = SourceLoader.loadSources("/banner/banners_url.oh");
        for (String banner : banners) {
            String[] kv = banner.split(",");
            if (kv[0].endsWith(path)) {
                entity.addTag(kv[1]);
            }
        }
        // 匹配响应中的关键字
        List<String> banners_body = SourceLoader.loadSources("/banner/banners_body.oh");
        for (String banner : banners_body) {
            String[] kv = banner.split(",");
            // TODO 怎么查找
            if (kv[0].equalsIgnoreCase("")) {
                entity.addTag(kv[1]);
            }
        }
    }
}

