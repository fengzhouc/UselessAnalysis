package com.alumm0x.scan.http.task;

import burp.IHttpRequestResponse;
import com.alumm0x.scan.LogEntry;
import com.alumm0x.scan.http.HeaderTools;
import com.alumm0x.scan.http.task.impl.TaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonStore;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public class IDOR extends TaskImpl {

    public static String name = "IDOR";
    public static String comments = "未授权检测。删除会话凭证重放请求，响应体与原来一致则存在未授权访问。";
    public static String fix = "排查系统所有服务接口及资源，确定哪些不需要授权即可访问，其他的均需要认证才可访问，若有角色划分的，则具体需要根据角色再鉴权限制访问。";

    public UselessTreeNodeEntity entity;

    public IDOR(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        /**
         * 未授权访问
         * 检测逻辑：删除会话凭证，如cookie，再发起请求
         * */

        //1、删除会话凭证，重新发起请求，与原始请求状态码一致则可能存在未授权访问
        List<String> new_headers = new ArrayList<String>();
        for (String header : BurpReqRespTools.getReqHeaders(entity.getRequestResponse())) {
            //删除cookie/authorization等可能的会话凭证头部
            String key = header.split(":")[0];
            if (HeaderTools.inNormal(key.toLowerCase(Locale.ROOT))) {
                new_headers.add(header);
            }
        }
        //新的请求包
        CommonStore.okHttpRequester.send(BurpReqRespTools.getUrlWithOutQuery(entity.getRequestResponse()),
                BurpReqRespTools.getMethod(entity.getRequestResponse()),
                new_headers,
                BurpReqRespTools.getQuery(entity.getRequestResponse()),
                BurpReqRespTools.getReqBody(entity.getRequestResponse()),
                BurpReqRespTools.getContentType(entity.getRequestResponse()),
                new IDORCallback(this));
    }
}

class IDORCallback implements Callback {
    TaskImpl task;
    UselessTreeNodeEntity entity;
    LogEntry logEntry;

    public IDORCallback(TaskImpl task){
        this.task = task;
        this.entity = ((IDOR)task).entity;
        this.logEntry = task.logAddToScanLogger(entity.getCurrent(), "IDOR");
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        logEntry.onFailure();
        CommonStore.logModel.update();
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call,response, BurpReqRespTools.getHttpService(entity.getRequestResponse()));
        logEntry.requestResponse = CommonStore.callbacks.saveBuffersToTempFiles(requestResponse);
        logEntry.Status = (short) response.code();
        if (response.isSuccessful()){
            // 响应体与原来相同，则存在问题
            if (Arrays.equals(BurpReqRespTools.getRespBody(requestResponse),BurpReqRespTools.getRespBody(entity.getRequestResponse()))) {
                logEntry.hasVuln();
            } else {
                logEntry.onResponse();
            }
        } else {
            logEntry.onResponse();
        }
        CommonStore.logModel.update();
    }
}