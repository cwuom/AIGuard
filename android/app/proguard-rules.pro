# 守护进程由 app_process 按类名反射启动，R8 看不到调用方
-keep class com.aiguard.daemon.DaemonMain { public static void main(java.lang.String[]); }
