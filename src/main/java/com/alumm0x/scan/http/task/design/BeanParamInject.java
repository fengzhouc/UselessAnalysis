package com.alumm0x.scan.http.task.design;

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
import org.json.JSONArray;
import org.json.JSONObject;


import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class BeanParamInject extends TaskImpl {

    private final StringBuilder stringBuilder;

    public static String name = "BeanParamInject";
    public static String comments = "Bean参数注入检测。构造原本没有的但响应中有的参数，设置异常值，查看响应中对应的字段是否改变，是则存在bean参数注入的风险。";
    public static String fix = "尽量不要图方便参数传递使用Bean对象，会造成预期外的操作。";

    public UselessTreeNodeEntity entity;

    public BeanParamInject(UselessTreeNodeEntity entity) {
        this.stringBuilder = new StringBuilder();
        this.entity = entity;
    }

    @Override
    public void run() {
        /**
         * 检测逻辑：当前只检测响应中会打印完整bean信息的情况
         * 1、解析响应获取参数名
         * 2、然后再请求中添加额外的参数进行重放
         * */
        // 1.分析请求及响应的字段信息
        // 2.找到有公共参数的地方，如果没有公共参数，则不继续
        // 3.然后提取出请求参数没有的，提取key:value
        // 4.在请求中添加参数，参数值根据原值进行微调
        // 5.重放后检查响应中的值是否也被修改
        // 疑问：按我理解框架会自动将json对象（不一定是json，还有form表单的也可以）转换为bean，一般bean就是getter/setter方法，如果不存在的字段会不会报错？
        // 实验结果：缺少或者冗余参数都不会报错，正常初始化

        //仅检测json数据的，目前使用json的多，form的很少了
        if (BurpReqRespTools.getContentType(entity.getRequestResponse()).contains("application/json")){
            String flag = "beanInject";
            //必须要有请求参数,且是json对象
            if ((BurpReqRespTools.getReqBody(entity.getRequestResponse())).length > 0 && new String(BurpReqRespTools.getReqBody(entity.getRequestResponse())).startsWith("{")) {
                //如果响应体信息比请求体信息少，则可能没有反馈bean信息，这样就无法检测了，pass
                if ((BurpReqRespTools.getRespBody(entity.getRequestResponse())).length > (BurpReqRespTools.getReqBody(entity.getRequestResponse())).length){
                    JSONObject reqJsonObject = new JSONObject(new String(BurpReqRespTools.getReqBody(entity.getRequestResponse())));
                    Map<String, Object> reqJsonMap = reqJsonObject.toMap();
                    if (new String(BurpReqRespTools.getRespBody(entity.getRequestResponse())).startsWith("{")) {
                        JSONObject respJsonObject = new JSONObject(new String(BurpReqRespTools.getRespBody(entity.getRequestResponse())));
                        Map<String, Object> respJsonMap = respJsonObject.toMap();
                        //1.分析并得出公共参数及缺少的参数
                        // -简单json对象,循环json对象，查看响应中是否有次key
                        // -复杂json对象,这里相对上面的需要注意的是需要定位是在哪个json对象中插入数据
                        Map<String, Object> beanJsonMap = getBeanJsonObjMap(reqJsonMap, respJsonMap);
                        //2.将缺少的参数注入到请求参数中并修改值，重放请求，循环所有缺少的参数
                        assert beanJsonMap != null;
                        jsonObjInject(beanJsonMap, reqJsonMap, flag);
                    }else if (new String(BurpReqRespTools.getRespBody(entity.getRequestResponse())).startsWith("[")){
                        JSONArray respJsonArray = new JSONArray(new String(BurpReqRespTools.getRespBody(entity.getRequestResponse())));
                        List<Object> respJsonMap = respJsonArray.toList();
                        //1.分析并得出公共参数及缺少的参数
                        // -简单json对象,循环json对象，查看响应中是否有次key
                        // -复杂json对象,这里相对上面的需要注意的是需要定位是在哪个json对象中插入数据
                        Map<String, Object> beanJsonMap = getBeanJsonObjMap(reqJsonMap, respJsonMap);
                        //2.将缺少的参数注入到请求参数中并修改值，重放请求，循环所有缺少的参数
                        assert beanJsonMap != null;
                        jsonObjInject(beanJsonMap, reqJsonMap, flag);
                    }
                    String new_body = stringBuilder.toString();
                    //3.查看响应中是否有篡改的值

                    //没有找到bean对象则不进行测试
                    if (!"".equalsIgnoreCase(new_body)){
                        CommonStore.callbacks.printError("\n###################BeanParamInject-Data########################\n" +
                                "##origin:\n" + new String(BurpReqRespTools.getReqBody(entity.getRequestResponse())) + "\n" +
                                "##temper:\n" + new_body);
                        //新的请求包
                        CommonStore.okHttpRequester.send(BurpReqRespTools.getUrlWithOutQuery(entity.getRequestResponse()),
                                BurpReqRespTools.getMethod(entity.getRequestResponse()),
                                BurpReqRespTools.getReqHeaders(entity.getRequestResponse()),
                                BurpReqRespTools.getQuery(entity.getRequestResponse()),
                                new_body.getBytes(StandardCharsets.UTF_8),
                                BurpReqRespTools.getContentType(entity.getRequestResponse()),
                                new BeanParamInjectCallback(this));
                    }else{
                        CommonStore.callbacks.printError("[BypassAuth] 不满足前置条件3: 通过遍历比对，没有构造出new_body.\n" +
                                "##url: "+ BurpReqRespTools.getUrl(entity.getRequestResponse()));
                    }
                }
            }else{
                CommonStore.callbacks.printError("[BypassAuth] 不满足前置条件2: 必须要是有请求参数，且是JsonObject.\n" +
                        "##url: "+ BurpReqRespTools.getUrl(entity.getRequestResponse()));
            }
        }else{
            CommonStore.callbacks.printError("[BypassAuth] 不满足前置条件1: ContentType必须要是'application/json'\n" +
                    "##url: "+ BurpReqRespTools.getUrl(entity.getRequestResponse()));
        }
    }
    //获取bean的jsonMap
    //如果响应中某个jsonObj包含所有请求中的jsonObj的key，则返回此jsonObj的map对象
    //只要当前json串中某个jsonObj满足要求即返回其map对象
    private static Map<String, Object> getBeanJsonObjMap(Map<String, Object> reqJsonMap, Map<String, Object> respJsonMap){
        Iterator<Map.Entry<String, Object>> iterator = respJsonMap.entrySet().iterator();
        Map<String, Object> result = null;
        int col = reqJsonMap.size();
        while (iterator.hasNext()){
            Map.Entry<String, Object> entry = iterator.next();
            String key = entry.getKey();
            if (reqJsonMap.containsKey(key)){ //当前jsonObjt是否包含请求中的key，包含则计数+1
                col -= 1;
                continue; //如果key包含了，那就不关心其值类型了，检查下一个
            }
            Object value = entry.getValue();
            if (value instanceof HashMap){ //json对象
                result = getBeanJsonObjMap(reqJsonMap, (Map<String, Object>) value);
                System.out.println("0-" + result);
            }else if (value instanceof ArrayList){ //json数组
                Iterator<Object> iteratorArray = ((ArrayList<Object>)value).iterator();
                while (iteratorArray.hasNext()){
                    Object obj = iteratorArray.next();
                    if (obj instanceof HashMap) { //有可能是对象数组
                        result = getBeanJsonObjMap(reqJsonMap, (Map<String, Object>) obj);
                        System.out.println("1-" + result);
                    }
                }
            }
        }
        // 只要包含所有请求中的jsonObj的key则返回
        if (col == 0){
            result = respJsonMap;
        }else if (result != null){
            return result;
        }
        return result;
    }

    //如果响应是json数组的话，则使用这个进行便利，获取bean
    private static Map<String, Object> getBeanJsonObjMap(Map<String, Object> reqJsonMap, List<Object> respJsonList){
        Iterator<Object> iteratorList = respJsonList.iterator();
        while(iteratorList.hasNext()) {
            Object valueList = iteratorList.next();
            if (valueList instanceof HashMap) {
                Map<String, Object> result = getBeanJsonObjMap(reqJsonMap, (Map<String, Object>)valueList);
                if (result != null){
                    return result;
                }
            }
        }
        return null;
    }

    private void write(String hash, boolean add){
        if (!add) {
            stringBuilder.append(hash);
        }else {
            stringBuilder.append(hash).append(",");
        }
    }
    // 参数注入的方法
    // 只会将reqJsonObj中没有key的值进行修改，设置为flag
    private void jsonObjInject(Map<String, Object> jsonMap,Map<String, Object> reqJsonMap, String inject) {
        write("{", false);
        Iterator<Map.Entry<String, Object>> iterator = jsonMap.entrySet().iterator();
        while (iterator.hasNext()){
            Map.Entry<String, Object> entry = iterator.next();
            String key = entry.getKey();
            Object value = entry.getValue();
            if (value instanceof HashMap){ //json对象
                write(String.format("\"%s\":{", key),false);
                Iterator<Map.Entry<String, Object>> iteratorValue = ((Map<String, Object>)value).entrySet().iterator();
                while (iteratorValue.hasNext()){
                    Map.Entry<String, Object> entryValue = iteratorValue.next();
                    if (entryValue instanceof HashMap) { //值也可能是对象
                        jsonObjInject((Map<String, Object>) entryValue, reqJsonMap, inject);
                    }else {//基础类型数据就是最里层的结果了 key:value
                        if (reqJsonMap.containsKey(entryValue.getKey())) {
                            write(String.format("\"%s\":\"%s\"", entryValue.getKey(), entryValue.getValue()), iteratorValue.hasNext());
                        }else {
                            write(String.format("\"%s\":\"%s\"", entryValue.getKey(), inject), iteratorValue.hasNext());
                        }
                    }
                }
                write("}", iterator.hasNext());
            }else if (value instanceof ArrayList){ //json数组
                write(String.format("\"%s\":[", key), false);
                Iterator<Object> iteratorArray = ((ArrayList<Object>)value).iterator();
                while (iteratorArray.hasNext()){
                    Object obj = iteratorArray.next();
                    if (obj instanceof HashMap) { //有可能是对象数组
                        jsonObjInject((Map<String, Object>) obj, reqJsonMap, inject);
                    }else { //要么就是基础类型数据了,就是最终结果了
                        write(String.format("\"%s\"", obj), iteratorArray.hasNext());
                    }
                }
                write("]", iterator.hasNext());
            }else {//基础类型数据就是最里层的结果了 key:value
                if (reqJsonMap.containsKey(key)) {
                    write(String.format("\"%s\":\"%s\"", key, value), iterator.hasNext());
                }else {
                    write(String.format("\"%s\":\"%s\"", key, inject), iterator.hasNext());
                }
            }
        }
        write("}", false);
    }
}

class BeanParamInjectCallback implements Callback {

    TaskImpl task;
    UselessTreeNodeEntity entity;
    LogEntry logEntry;

    public BeanParamInjectCallback(TaskImpl task){
        this.task = task;
        this.entity = ((BeanParamInject)task).entity;
        this.logEntry = task.logAddToScanLogger(entity.getCurrent(), "BeanParamInject");
    }
    @Override
    public void onFailure(@NotNull Call call, @NotNull IOException e) {
        logEntry.onFailure();
        CommonStore.logModel.update();
        CommonStore.callbacks.printError("[BeanParamInjectCallback]" + e.getMessage());
        logEntry.Comments = e.getMessage();
    }

    @Override
    public void onResponse(@NotNull Call call, @NotNull Response response) throws IOException {
        IHttpRequestResponse requestResponse = BurpReqRespTools.makeBurpReqRespFormOkhttp(call,response, BurpReqRespTools.getHttpService(entity.getRequestResponse()));
        logEntry.requestResponse = CommonStore.callbacks.saveBuffersToTempFiles(requestResponse);
        logEntry.Status = (short) response.code();
        //如果响应成功，则检查值是否被修改
        if (response.isSuccessful()) {
            // 检查响应中是否存在flag
            if (new String(BurpReqRespTools.getRespBody(requestResponse)).contains("beanInject")) {
                logEntry.hasVuln();
                entity.color = "red";
            }
        }else { //啥情况会不成功，做了些数据校验的时候，比如这个字段只允许String，我改成int，可能就会报错，那报错就可能就是用了bean
            logEntry.onResponse();
            logEntry.Comments = "异常参数报错了，自己搞搞看呢.";
        }
        CommonStore.logModel.update();
    }
}