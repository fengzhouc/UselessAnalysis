package com.alumm0x.scan.http.task;

import burp.IHttpRequestResponse;
import com.alumm0x.scan.LogEntry;
import com.alumm0x.scan.http.task.impl.TaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonStore;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class UploadSecure extends TaskImpl {

    public static String name = "UploadType";
    public static String comments = "任意文件上传检测。会修改上传的文件后缀及content-type，上传成功则可能存在问题。";
    public static String fix = "等保要求: 需要根据业务场景需要限制上传文件类型。";

    public UselessTreeNodeEntity entity;

    public UploadSecure(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }

    @Override
    public void run() {
        /**
         * 检测逻辑
         * 1、修改文件名类型
         * 2、修改请求体中content-type的类型，有些是根据这里去设置文件类型的
         * */
        //限定contentype的头部为文件上传的类型
        if (BurpReqRespTools.getContentType(entity.getRequestResponse()).contains("multipart/form-data")){
            String fileName = "shell.php";
            //如果有body参数，需要多body参数进行测试
            if (BurpReqRespTools.getReqBody(entity.getRequestResponse()).length > 0){
                //1.检查后缀名
                String regex = "filename=\"(.*?)\""; //分组获取文件名
                Pattern pattern = Pattern.compile(regex);
                Matcher matcher = pattern.matcher(new String(BurpReqRespTools.getReqBody(entity.getRequestResponse())));
                if (matcher.find()){//没匹配到则不进行后续验证
                    String fileOrigin = matcher.group(1);
                    // 修改为别的文件名
                    String req_body = new String(BurpReqRespTools.getReqBody(entity.getRequestResponse())).replace(fileOrigin, fileName);
                    //新的请求包,检查任意文件上传
                    CommonStore.okHttpRequester.send(BurpReqRespTools.getUrlWithOutQuery(entity.getRequestResponse()),
                            BurpReqRespTools.getMethod(entity.getRequestResponse()),
                            BurpReqRespTools.getReqHeaders(entity.getRequestResponse()),
                            BurpReqRespTools.getQuery(entity.getRequestResponse()),
                            req_body.getBytes(StandardCharsets.UTF_8),
                            BurpReqRespTools.getContentType(entity.getRequestResponse()),
                            new UploadSecureCallback(this));
                    //2.修改content-type
                    String regex1 = "Content-Type:\\s(.*?)\\s"; //分组获取文件名
                    Pattern pattern1 = Pattern.compile(regex1);
                    Matcher matcher1 = pattern1.matcher(new String(BurpReqRespTools.getReqBody(entity.getRequestResponse())));
                    if (!matcher1.find()){//没匹配到则不进行后续验证
                        String ctOrigin = matcher1.group(1);
                        // 修改为别的content-typet,在上面修改后缀的基础下
                        String req_body1 = req_body.replace(ctOrigin, "application/x-httpd-php");
                        //新的请求包
                        CommonStore.okHttpRequester.send(BurpReqRespTools.getUrlWithOutQuery(entity.getRequestResponse()),
                                BurpReqRespTools.getMethod(entity.getRequestResponse()),
                                BurpReqRespTools.getReqHeaders(entity.getRequestResponse()),
                                BurpReqRespTools.getQuery(entity.getRequestResponse()),
                                req_body1.getBytes(StandardCharsets.UTF_8),
                                BurpReqRespTools.getContentType(entity.getRequestResponse()),
                                new UploadSecureCallback(this));
                    }
                }
            }
        }
    }

}

class UploadSecureCallback implements Callback {

    TaskImpl task;
    UselessTreeNodeEntity entity;
    LogEntry logEntry;

    public UploadSecureCallback(TaskImpl task){
        this.task = task;
        this.entity = ((UploadSecure)task).entity;
        this.logEntry = task.logAddToScanLogger(entity.getCurrent(), "UploadType");
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        logEntry.onFailure();
        CommonStore.logModel.update();
        CommonStore.callbacks.printError("[UploadSecureCallback]" + e.getMessage());
        logEntry.Comments = e.getMessage();
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call,response, BurpReqRespTools.getHttpService(entity.getRequestResponse()));
        logEntry.requestResponse = CommonStore.callbacks.saveBuffersToTempFiles(requestResponse);
        logEntry.Status = (short) response.code();
        if (response.isSuccessful()){
            logEntry.hasVuln();
            entity.color = "red";
        } else {
            logEntry.onResponse();
        }
        CommonStore.logModel.update();
    }
}