package com.alumm0x.scan.http.task;

import burp.IHttpRequestResponse;
import com.alumm0x.scan.LogEntry;
import com.alumm0x.scan.http.task.impl.TaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonStore;
import com.alumm0x.util.param.json.ParamHandlerImpl;
import com.alumm0x.util.param.json.ParamKeyValue;
import com.alumm0x.util.param.json.JsonTools;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class JWTSignNone extends TaskImpl {

    public static String name = "JWTSignNone";
    public static String comments = "JWT未校验签名检测。签名设置为none，重放请求查看响应是否一样。(CVE-2015-2951)";
    public static String fix = "开启签名校验，保证完整性。";

    public UselessTreeNodeEntity entity;

    public JWTSignNone(UselessTreeNodeEntity entity) {
        this.entity = entity;
    }
    @Override
    public void run() {
        // 检查json数据
        if (BurpReqRespTools.getContentType(entity.getRequestResponse()).contains("application/json")
                && BurpReqRespTools.getReqBody(entity.getRequestResponse()).length > 0
                && new String(BurpReqRespTools.getReqBody(entity.getRequestResponse())).startsWith("{")){
            JsonTools tools = new JsonTools();
            try {
                tools.jsonObjHandler(JsonTools.jsonObjectToMap(new String(BurpReqRespTools.getReqBody(entity.getRequestResponse()))), new ParamHandlerImpl() {
                    @Override
                    public ParamKeyValue handler(Object key, Object value) {
                        byte[] decode = CommonStore.helpers.base64Decode(value.toString());
                        if (new String(decode).contains("\"alg\"")) {
                            String jwt_header = "";
                            String jwt_payload = "";
                            for (String t : Arrays.copyOfRange(value.toString().split("\\."),0,2)) {
                                JsonTools tools = new JsonTools();
                                tools.jsonObjHandler(JsonTools.jsonObjectToMap(t), new ParamHandlerImpl() {
                                    @Override
                                    public ParamKeyValue handler(Object key, Object value) {
                                        if (key.toString().equals("alg")) {
                                            return new ParamKeyValue(key,"none");
                                        }
                                        return new ParamKeyValue(key,value);
                                    }
                                });
                                if (tools.NEW_JSON.toString().contains("alg")) {
                                    jwt_header = tools.NEW_JSON.toString();
                                } else {
                                    jwt_payload = tools.NEW_JSON.toString();
                                }
                            }
                            return new ParamKeyValue(key, String.format("%s.%s", CommonStore.helpers.base64Encode(jwt_header), CommonStore.helpers.base64Encode(jwt_payload)));
                        }
                        return new ParamKeyValue(key, value);
                    }
                });
            } catch (Exception e) {
                CommonStore.callbacks.printError(e.getMessage());
            }

            //新的请求包
            CommonStore.okHttpRequester.send(BurpReqRespTools.getUrlWithOutQuery(entity.getRequestResponse()),
                    BurpReqRespTools.getMethod(entity.getRequestResponse()),
                    headerHandler(),
                    queryHandler(BurpReqRespTools.getQuery(entity.getRequestResponse())),
                    tools.NEW_JSON.toString().getBytes(StandardCharsets.UTF_8),
                    BurpReqRespTools.getContentType(entity.getRequestResponse()),
                    new JWTSignNoneCallback(this));
        }
    }

    /**
     * 处理查询参数中的jwt，去掉签名部分
     * @param querystring 完整的查询参数
     * @return 返回修改后的查询参数
     */
    public String queryHandler(String querystring) {
        for (Map.Entry<String, String> entry :
                BurpReqRespTools.getQueryMap(entity.getRequestResponse()).entrySet()) {
            byte[] decode = CommonStore.helpers.base64Decode(entry.getValue());
            if (new String(decode).contains("\"alg\"")) {
                String jwt_header = "";
                String jwt_payload = "";
                for (String t : Arrays.copyOfRange(entry.getValue().split("\\."),0,2)) {
                    JsonTools tools = new JsonTools();
                    tools.jsonObjHandler(JsonTools.jsonObjectToMap(t), new ParamHandlerImpl() {
                        @Override
                        public ParamKeyValue handler(Object key, Object value) {
                            if (key.toString().equals("alg")) {
                                return new ParamKeyValue(key,"none");
                            }
                            return new ParamKeyValue(key,value);
                        }
                    });
                    if (tools.NEW_JSON.toString().contains("alg")) {
                        jwt_header = tools.NEW_JSON.toString();
                    } else {
                        jwt_payload = tools.NEW_JSON.toString();
                    }
                }
                return querystring.replace(entry.getValue(), String.format("%s.%s", CommonStore.helpers.base64Encode(jwt_header), CommonStore.helpers.base64Encode(jwt_payload)));
            }
        }
        return null;
    }

    /**
     * 处理请求头中的jwt，删除其签名部分
     * @return List<String>
     */
    public List<String> headerHandler(){
        List<String> new_header = new ArrayList<>();
        for (String header :
                BurpReqRespTools.getReqHeaders(entity.getRequestResponse())) {
            String value = header.split("=")[1];
            byte[] decode = CommonStore.helpers.base64Decode(value);
            if (new String(decode).contains("\"alg\"")) {
                String jwt_header = "";
                String jwt_payload = "";
                for (String t : Arrays.copyOfRange(value.split("\\."),0,2)) {
                    JsonTools tools = new JsonTools();
                    tools.jsonObjHandler(JsonTools.jsonObjectToMap(t), new ParamHandlerImpl() {
                        @Override
                        public ParamKeyValue handler(Object key, Object value) {
                            if (key.toString().equals("alg")) {
                                return new ParamKeyValue(key,"none");
                            }
                            return new ParamKeyValue(key,value);
                        }
                    });
                    if (tools.NEW_JSON.toString().contains("alg")) {
                        jwt_header = tools.NEW_JSON.toString();
                    } else {
                        jwt_payload = tools.NEW_JSON.toString();
                    }
                }
                header = header.replace(value, String.format("%s.%s", CommonStore.helpers.base64Encode(jwt_header), CommonStore.helpers.base64Encode(jwt_payload)));
            }
            new_header.add(header);
        }
        return new_header;
    }
}

class JWTSignNoneCallback implements Callback {
    TaskImpl task;
    UselessTreeNodeEntity entity;
    LogEntry logEntry;

    public JWTSignNoneCallback(TaskImpl task){
        this.task = task;
        this.entity = ((JWTSensitiveMessage)task).entity;
        this.logEntry = task.logAddToScanLogger(entity.getCurrent(), "JWTWithOutSign");
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