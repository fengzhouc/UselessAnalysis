package com.alumm0x.util.jsontools;

/**
 * 用户保存健值对
 */
public class JsonKeyValue {

    private final Object Key;
    private final Object Value;
    private boolean isFind = false;

    public JsonKeyValue(Object key, Object value) {
        this.Key = key;
        this.Value = value;
    }

    public Object getKey() {
        return Key;
    }

    public Object getValue() {
        return Value;
    }

    public boolean isFind() {
        return isFind;
    }

    public void setFind(boolean find) {
        isFind = find;
    }
}
