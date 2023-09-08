package com.alumm0x.scan;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Set;

import org.reflections.Reflections;

import com.alumm0x.scan.http.task.impl.VulTaskImpl;
import com.alumm0x.tree.UselessTreeNodeEntity;
import com.alumm0x.util.CommonStore;

public class VulScanEngine  {

    public static Set<Class<? extends VulTaskImpl>> tasks;

    // 获取VulTaskImpl的子类，其就是实现的所有检测项
    static {
        Reflections reflections = new Reflections("com.alumm0x.scan.http.task");
        tasks = reflections.getSubTypesOf(VulTaskImpl.class);
    }

    public static void addScan(String poc, UselessTreeNodeEntity entity) {

        // 遍历tasks找到指定的poc
        for (Class<? extends VulTaskImpl> task : tasks) {
            if (task.getSimpleName().equalsIgnoreCase(poc)) {
                try {
                    // 反射获取实例
                    Constructor<?> cons = task.getConstructor(UselessTreeNodeEntity.class);
                    // 获取待调用的方法
                    Method run = task.getMethod("run");
                    // 运行方法
                    run.invoke(cons.newInstance(entity));
                } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InstantiationException e) {
                    CommonStore.callbacks.printError("[VulScanEngine] " + e.getClass().getSimpleName() + " " + e.getMessage());
                } catch (InvocationTargetException e) {
                    CommonStore.callbacks.printError("[VulScanEngine] " + e.getClass().getSimpleName() + " " + e.getTargetException().toString());
                }
            }
        }
    }
}
