package com.alumm0x.util.param.json;

import org.json.JSONObject;

import java.util.*;

/**
 * 用于遍历json传，并进行一些修改或判断是否存在某数据
 */
public class JsonTools {

    // 保存篡改的json串
    public final StringBuilder NEW_JSON; //新的json串

    public JsonTools(){
        this.NEW_JSON = new StringBuilder();
    }

    //修改后还原json字符串
    private void write(String hash, boolean add){
        if (!add) {
            NEW_JSON.append(hash);
        }else {
            NEW_JSON.append(hash).append(",");
        }
    }
    /**
     * 遍历json对象，每个值中插入标记
     * @niject 注入的参数
     * */
    public void jsonObjHandler(Map<String, Object> jsonMap, ParamHandlerImpl handler) {
        write("{", false);
        Iterator<Map.Entry<String, Object>> iterator = jsonMap.entrySet().iterator();
        while (iterator.hasNext()){
            Map.Entry<String, Object> entry = iterator.next();
            String key = entry.getKey();
            Object value = entry.getValue();
            if (value instanceof HashMap){ //json对象
//                System.out.println("Key = " + key + " //JsonObject");
                write(String.format("\"%s\":{", key),false);
                Iterator<Map.Entry<String, Object>> iteratorValue = ((Map<String, Object>)value).entrySet().iterator();
                while (iteratorValue.hasNext()){
                    Map.Entry<String, Object> entryValue = iteratorValue.next();
                    if (entryValue instanceof HashMap) { //值也可能是对象
                        jsonObjHandler((Map<String, Object>) entryValue, handler);
                    }else {//基础类型数据就是最里层的结果了 key:value
//                        System.out.println("--Key = " + entryValue.getKey() + ", Value = " + entryValue.getValue() + ", type: " + entryValue.getValue().getClass());
                        ParamKeyValue paramKeyValue = handler.handler(entryValue.getKey(), entryValue.getValue());
                        write(String.format("\"%s\":\"%s\"", paramKeyValue.getKey(), paramKeyValue.getValue()), iteratorValue.hasNext());
                    }
                }
                write("}", iterator.hasNext());
            }else if (value instanceof ArrayList){ //json数组
                write(String.format("\"%s\":[", key), false);
                Iterator<Object> iteratorArray = ((ArrayList<Object>)value).iterator();
//                System.out.println("Key = " + key + " //JsonArray");
                while (iteratorArray.hasNext()){
                    Object obj = iteratorArray.next();
                    if (obj instanceof HashMap) { //有可能是对象数组
                        jsonObjHandler((Map<String, Object>) obj, handler);
                    }else { //要么就是基础类型数据了,就是最终结果了
//                        System.out.println("--Value = " + obj + ", type: " + obj.getClass());
                        ParamKeyValue paramKeyValue = handler.handler(key, obj);
                        write(String.format("\"%s\"", paramKeyValue.getValue()), iteratorArray.hasNext());
                    }
                }
                write("]", iterator.hasNext());
            }else {//基础类型数据就是最里层的结果了 key:value
                ParamKeyValue paramKeyValue = handler.handler(key, value);
                write(String.format("\"%s\":\"%s\"", paramKeyValue.getKey(), paramKeyValue.getValue()), iterator.hasNext());
//                System.out.println(String.format("Key = %s  Value = %s, type: %s",key, value, value.getClass()));
            }
        }
        write("}", false);
    }

    /**
     * 遍历json数组，每个值中插入标记
     * @niject 注入的参数
     * */
    public void jsonArrHandler(List<Object> jsonList, ParamHandlerImpl handler) {
        write("[", false);
        Iterator<Object> iterator = jsonList.iterator();
        while (iterator.hasNext()){
            Object value = iterator.next();
//            System.out.println(value + " ,type: " + value.getClass());
            if (value instanceof HashMap){ //json对象数组
                jsonObjHandler((Map<String, Object>)value, handler);
            }else {//基础类型数据就是最里层的结果了 value，value1，value2
                ParamKeyValue paramKeyValue = handler.handler("", value);
                write(String.format("\"%s\"", paramKeyValue.getValue()), iterator.hasNext());
            }
        }
        write("]", false);
    }

    /**
     * 解析json字符串里的对象，放回 Map
     * @param object
     * @return Map
     */
    public static Map<String,Object> jsonObjectToMap(Object object) {
        JSONObject jsonObject = new JSONObject(object.toString());
        Map<String,Object> objectMap = jsonObject.toMap();
        // 打印健值对看看
        // objectMap.forEach((key,value) -> System.out.println(key + "=" + value));
        return objectMap;
    }
}
