package com.alumm0x.util.jsontools;

/**
 * 用于处理json数据的类，可以继承复写相关方法
 */
public abstract class JsonHandlerImpl {
    /**
     * 用于实现吹了健值对的逻辑（如果想实现查找的话，可以返回null，这样最上层也会返回null，这样就可以感知到存在查找的目标）
     * @param key 健
     * @param value 值
     * @return JsonKeyValue
     */
    abstract public JsonKeyValue handler(Object key, Object value);
}

