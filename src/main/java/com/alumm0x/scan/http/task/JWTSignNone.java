package com.alumm0x.scan.http.task;

import burp.IHttpRequestResponse;
import com.alumm0x.scan.LogEntry;
import com.alumm0x.scan.http.task.impl.TaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.BurpReqRespTools;
import com.alumm0x.util.CommonStore;
import com.alumm0x.util.param.ParamHandlerImpl;
import com.alumm0x.util.param.ParamKeyValue;
import com.alumm0x.util.param.form.FormTools;
import com.alumm0x.util.param.header.HeaderTools;
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
import java.util.Objects;

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
        JsonTools tools = new JsonTools();
        if (BurpReqRespTools.getContentType(entity.getRequestResponse()).contains("application/json")
                && BurpReqRespTools.getReqBody(entity.getRequestResponse()).length > 0
                && new String(BurpReqRespTools.getReqBody(entity.getRequestResponse())).startsWith("{")) {
            try {
                tools.jsonObjHandler(Objects.requireNonNull(JsonTools.jsonObjectToMap(new String(BurpReqRespTools.getReqBody(entity.getRequestResponse())))), new ParamHandlerImpl() {
                    @Override
                    public List<ParamKeyValue> handler(Object key, Object value) {
                        List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                        byte[] decode = CommonStore.helpers.base64Decode(value.toString());
                        if (new String(decode).contains("\"alg\"")) {
                            String jwt_header = "";
                            String jwt_payload = "";
                            for (String t : Arrays.copyOfRange(value.toString().split("\\."), 0, 2)) {
                                JsonTools tools = new JsonTools();
                                tools.jsonObjHandler(Objects.requireNonNull(JsonTools.jsonObjectToMap(new String(CommonStore.helpers.base64Decode(t)))), new ParamHandlerImpl() {
                                    @Override
                                    public List<ParamKeyValue> handler(Object key, Object value) {
                                        List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                                        if (key.toString().equals("alg")) {
                                            paramKeyValues.add(new ParamKeyValue(key, "none"));
                                        } else {
                                            paramKeyValues.add(new ParamKeyValue(key, value));
                                        }
                                        return paramKeyValues;
                                    }
                                });
                                if (tools.toString().contains("alg")) {
                                    jwt_header = tools.toString();
                                } else {
                                    jwt_payload = tools.toString();
                                }
                            }
                            paramKeyValues.add(new ParamKeyValue(key, String.format("%s.%s", CommonStore.helpers.base64Encode(jwt_header), CommonStore.helpers.base64Encode(jwt_payload))));
                        } else {
                            paramKeyValues.add(new ParamKeyValue(key, value));
                        }
                        return paramKeyValues;
                    }

                });
            } catch (Exception e) {
                CommonStore.callbacks.printError(e.getMessage());
            }
        }
        // 查询参数
        FormTools query = new FormTools();
        query.formHandler(BurpReqRespTools.getQueryMap(entity.getRequestResponse()), new ParamHandlerImpl() {
            @Override
            public List<ParamKeyValue> handler(Object key, Object value) {
                List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                byte[] decode = CommonStore.helpers.base64Decode(value.toString());
                if (new String(decode).contains("\"alg\"")) {
                    String jwt_header = "";
                    String jwt_payload = "";
                    for (String t : Arrays.copyOfRange(value.toString().split("\\."), 0, 2)) {
                        JsonTools tools = new JsonTools();
                        tools.jsonObjHandler(Objects.requireNonNull(JsonTools.jsonObjectToMap(new String(CommonStore.helpers.base64Decode(t)))), new ParamHandlerImpl() {
                            @Override
                            public List<ParamKeyValue> handler(Object key, Object value) {
                                List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                                if (key.toString().equals("alg")) {
                                    paramKeyValues.add(new ParamKeyValue(key, "none"));
                                } else {
                                    paramKeyValues.add(new ParamKeyValue(key, value));
                                }
                                return paramKeyValues;
                            }
                        });
                        if (tools.toString().contains("alg")) {
                            jwt_header = tools.toString();
                        } else {
                            jwt_payload = tools.toString();
                        }
                    }
                    paramKeyValues.add(new ParamKeyValue(key, String.format("%s.%s", CommonStore.helpers.base64Encode(jwt_header), CommonStore.helpers.base64Encode(jwt_payload))));
                } else {
                    paramKeyValues.add(new ParamKeyValue(key, value));
                }
                return paramKeyValues;
            }
        });
        // 处理header的数据
        HeaderTools header = new HeaderTools();
        header.headerHandler(BurpReqRespTools.getReqHeadersToMap(entity.getRequestResponse()), new ParamHandlerImpl() {
            @Override
            public List<ParamKeyValue> handler(Object key, Object value) {
                List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                byte[] decode = CommonStore.helpers.base64Decode(value.toString());
                if (new String(decode).contains("\"alg\"")) {
                    String jwt_header = "";
                    String jwt_payload = "";
                    for (String t : Arrays.copyOfRange(value.toString().split("\\."), 0, 2)) {
                        JsonTools tools = new JsonTools();
                        tools.jsonObjHandler(Objects.requireNonNull(JsonTools.jsonObjectToMap(new String(CommonStore.helpers.base64Decode(t)))), new ParamHandlerImpl() {
                            @Override
                            public List<ParamKeyValue> handler(Object key, Object value) {
                                List<ParamKeyValue> paramKeyValues = new ArrayList<>();
                                if (key.toString().equals("alg")) {
                                    paramKeyValues.add(new ParamKeyValue(key, "none"));
                                } else {
                                    paramKeyValues.add(new ParamKeyValue(key, value));
                                }
                                return paramKeyValues;
                            }
                        });
                        if (tools.toString().contains("alg")) {
                            jwt_header = tools.toString();
                        } else {
                            jwt_payload = tools.toString();
                        }
                    }
                    paramKeyValues.add(new ParamKeyValue(key, String.format("%s.%s", CommonStore.helpers.base64Encode(jwt_header), CommonStore.helpers.base64Encode(jwt_payload))));
                } else {
                    paramKeyValues.add(new ParamKeyValue(key, value));
                }
                return paramKeyValues;
            }
        });
        // 因为不知道是哪个参数有jwt，所以query/body/header都处理一边，再请求一次
        //新的请求包

            CommonStore.okHttpRequester.send(BurpReqRespTools.getUrlWithOutQuery(entity.getRequestResponse()),
                    BurpReqRespTools.getMethod(entity.getRequestResponse()),
                    header.NEW_HEADER,
                    query.toString(),
                    tools.toString().getBytes(StandardCharsets.UTF_8),
                    BurpReqRespTools.getContentType(entity.getRequestResponse()),
                    new JWTSignNoneCallback(this));
    }
}

class JWTSignNoneCallback implements Callback {
    TaskImpl task;
    UselessTreeNodeEntity entity;
    LogEntry logEntry;

    public JWTSignNoneCallback(TaskImpl task){
        this.task = task;
        this.entity = ((JWTSignNone)task).entity;
        this.logEntry = task.logAddToScanLogger(entity.getCurrent(), "JWTSignNone");
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        logEntry.onFailure();
        CommonStore.logModel.update();
        CommonStore.callbacks.printError("[JWTSignNoneCallback]" + e.getMessage());
        logEntry.Comments = e.getMessage();
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call,response, BurpReqRespTools.getHttpService(entity.getRequestResponse()));
        logEntry.requestResponse = CommonStore.callbacks.saveBuffersToTempFiles(requestResponse);
        logEntry.Status = (short) response.code();
        if (response.code() == BurpReqRespTools.getStatus(entity.getRequestResponse())){
            // 响应体与原来相同，则存在问题
            if (Arrays.equals(BurpReqRespTools.getRespBody(requestResponse),BurpReqRespTools.getRespBody(entity.getRequestResponse()))) {
                logEntry.hasVuln();
                entity.color = "red";
            } else {
                logEntry.onResponse();
            }
        } else {
            logEntry.onResponse();
        }
        CommonStore.logModel.update();
    }
}