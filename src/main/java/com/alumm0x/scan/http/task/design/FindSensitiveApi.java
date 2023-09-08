package com.alumm0x.scan.http.task.design;

import burp.IHttpRequestResponse;
import com.alumm0x.scan.LogEntry;
import com.alumm0x.scan.http.task.impl.TaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonStore;
import com.alumm0x.util.SourceLoader;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FindSensitiveApi extends TaskImpl {

    public static String name = "FindSensitiveApi";
    public static String comments = "扫描是否有敏感api,如swagger-doc; api指纹使用/banner/banners_url.oh";
    public static String fix = "一般禁止公开,因为要么是存在漏洞的可获取主机权限,要么就是会泄漏敏感信息的。";

    public UselessTreeNodeEntity entity;

    public FindSensitiveApi(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {

        //遍历所有指纹，进行请求验证
        for (String url_banner : SourceLoader.loadSources("/banner/banners_url.oh")) {
            String[] banner =url_banner.split(",",2);
            // 通过正则获取url根部，用于构造网站的根节点
            String regex = "http[s]?://(.*?)/+";
            Pattern pattern = Pattern.compile(regex);
            Matcher m = pattern.matcher(entity.getCurrent());
            if (m.find()){
                String url =m.group() + banner[0];
                //新的请求包
                CommonStore.okHttpRequester.get(url, new FindSensitiveApiCallback(this, url));
            }
        }
    }
}

class FindSensitiveApiCallback implements Callback {
    TaskImpl task;
    UselessTreeNodeEntity entity;
    LogEntry logEntry;

    public FindSensitiveApiCallback(TaskImpl task, String url){
        this.task = task;
        this.entity = ((FindSensitiveApi)task).entity;
        this.logEntry = task.logAddToScanLogger(url, FindSensitiveApi.class.getSimpleName());
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        logEntry.onFailure();
        CommonStore.logModel.update();
        CommonStore.callbacks.printError("[FindSensitiveApiCallback]" + e.getMessage());
        logEntry.Comments = e.getMessage();
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call,response, BurpReqRespTools.getHttpService(entity.getRequestResponse()));
        logEntry.requestResponse = CommonStore.callbacks.saveBuffersToTempFiles(requestResponse);
        logEntry.Status = (short) response.code();
        if (response.code() != 404){
            // 状态码不存在则认为存在该API
            logEntry.hasVuln();
        } else {
            logEntry.onResponse();
        }
        CommonStore.logModel.update();
    }
}