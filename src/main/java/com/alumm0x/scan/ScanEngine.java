package com.alumm0x.scan;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Set;

import org.reflections.Reflections;

import com.alumm0x.scan.http.task.impl.TaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.CommonStore;

public class ScanEngine  {

    public static Set<Class<? extends TaskImpl>> tasks;

    // 获取TaskImpl的子类，其就是实现的所有检测项
    static {
        Reflections reflections = new Reflections("com.alumm0x");
        tasks = reflections.getSubTypesOf(TaskImpl.class);
    }

    public static void addScan(String poc, UselessTreeNodeEntity entity) {

        // 遍历tasks找到指定的poc
        for (Class<? extends TaskImpl> task : tasks) {
            // 使用startWith进行匹配的原因是一个问题可能有多个检测类，这样UI上可以仅写前缀即可
            if (task.getSimpleName().startsWith(poc)) {
                try {
                    // 反射获取实例
                    Constructor<?> cons = task.getConstructor(UselessTreeNodeEntity.class);
                    // 获取待调用的方法
                    Method run = task.getMethod("run");
                    // 运行方法
                    run.invoke(cons.newInstance(entity));
                } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException | InstantiationException e) {
                    CommonStore.callbacks.printError("[ScanEngine] " + e.getMessage());
                }
            }
        }
    }
}
