# 创高体育（net.crigh.cgsport）校园跑反作弊机制技术分析

> 分析对象：创高体育 Android 3.0.1（versionCode 119，targetSdk 28，arm64-v8a）
> 包名：`net.crigh.cgsport`
> 方法：APK 静态分析（jadx / baksmali / 自写 DEX 与 AXML 解析）+ 运行时落盘产物分析 + IDA 静态
> 本文只做机制说明，不含任何绕过手段。

---

## 0. TL;DR

- 判定权在**服务端**。客户端只做三件事：**采数据（逐点带速度/精度/步数）、打标记（精度等级、暂停点、打卡）、拦工具（模拟器/多开/Frida/Xposed）**。
- 客户端上真正"活着"的检测只有 **10 个判定点**；另有 **9 处写了但没接线的死代码**（见第 7 节），这是网上很多二手资料最容易搞错的地方。
- 最外层拦住模拟器的不是著名的"模拟器打分表"，而是 **两个传感器探测**（光线 TYPE_LIGHT=5、环境温度 TYPE_AMBIENT_TEMPERATURE=13 返回 null 即判定）。
- 请求加密/验签被藏在一个**伪装成高德定位 SDK 的 so** 里（`libAMapSDK_Location_v6_6_0.so`，1.1 MB，只有一个 JNI 导出，含 tiny-AES）。

---

## 1. 分析路径（可复现）

```
1) adb 提取 APK： pm path net.crigh.cgsport  →  adb pull base.apk
2) 壳结构： Application = com.security.shell.V5App
          assets/dsnapk0000.vd (231,484 B) / dsnstub000.vd (53,524 B)，头部 "TUH:"
3) 运行时脱壳落盘： /data/user_de/0/net.crigh.cgsport/dsn0/dex/libdsn_<hash>.jar
          内含 classes.dex / classes2.dex / classes3.dex（27.2 MB，21,465 类）
4) 反汇编： baksmali 3.0.10 → 全量 smali（保留 .source 原始类名，这是还原混淆类名的关键）
5) 资源： aapt2 dump strings / resources → 文案与资源 ID 对应
6) native： libstub000.so / libapk0000.so（IDA，365 函数）+ libAMapSDK_Location_v6_6_0.so
```

混淆类名还原技巧：壳只改了类名，**没删 `.source` 属性**。全量扫 21,465 个 smali 文件的 `.source`
即可得到"混淆类名 → 原始 .java 文件名"的完整映射（本文所有"原始类名"均由此得出）。

---

## 2. 总体架构：三层

```
┌───────────────────────────────────────────────────────────────┐
│ L1 环境层（每次 Activity.onResume 都跑，命中即 Toast + finish）│
│    EasyProtectorLib（开源库，混淆进 classes.dex）              │
│      ├ SecurityCheckUtil     root/Xposed/反调试/签名/充电       │
│      ├ VirtualApkCheckUtil   多开、虚拟空间、分身框架           │
│      ├ EmulatorCheckUtil     模拟器打分（本版本未接线）          │
│      └ 端口探测 27042/27047 → 加固壳 native                    │
│    SecurityCheckUtils（应用自研）                              │
│      ├ getRunningServices 扫 "frida"                          │
│      └ getPackageInfo("com.lerist.fakelocation")              │
│    Utils.涞魾墨辺湔閞秣纑萖   Build 属性 + 传感器 → 模拟器判定   │
├───────────────────────────────────────────────────────────────┤
│ L2 采集层（跑步过程中逐点）                                     │
│    AMAPLocationService_   精度分级 / 定位类型过滤 / 点位落库     │
│    SportLocationService   分钟跑                                │
│    RoomSportService       宿舍跑（STEP_COUNTER/STEP_DETECTOR/加速度计）│
│    AMap SDK               isFromMockProvider / QualityReport    │
├───────────────────────────────────────────────────────────────┤
│ L3 服务端判定层（客户端只上传 + 展示回执）                        │
│    POST api/l/v7/savesports (jsonsports)                        │
│    GET  api/l/v6.1/sports/invalidconf → InvalidConfig 码表      │
└───────────────────────────────────────────────────────────────┘
```

---

## 3. 环境与设备检测（逐条）

### 3.1 每次 onResume 的硬闸门

文件：`smali/classes3/net/crigh/library/base/BaseActivity.smali`

| 序 | 调用 | 检测内容 | 命中后果 |
|---|---|---|---|
| 1 | EasyProtectorLib.猱繮滤冕() | Xposed（XposedBridge）| Toast + finish |
| 2 | SecurityCheckUtils.躽羦鶽挴毋惛(0x69A2) / (0x69A7) | **Frida 端口 27042 / 27047** | Toast + finish |
| 3 | SecurityCheckUtils.虂紆肯趝噐鱔湹() | 装了 `com.lerist.fakelocation`（FakeLocation/影梭）| Toast + finish |
| 4 | isOpenMore() | 多开/虚拟空间（3 判并联 + 1）| Toast + finish |
| 5 | EasyProtectorLib.帋岫() | 反调试（/proc/<pid>/status 的 TracerPid）| Toast + finish |

前置：`isAgree`（隐私协议）为 true，否则整套跳过。
另：`MyApplication.onCreate()` 调 EasyProtectorLib.眽归脇嘾霎緍爮踨墿厈磧()（Xposed disableHooks）。

### 3.2 多开 / 虚拟空间

文件：`smali/classes/縰丒…/熏燵婨左崘畱噛淜/櫼螉彬彆/鉩槣锉孤鋙迖执籢趬.smali`（.source VirtualApkCheckUtil.java）

| 手段 | 具体 |
|---|---|
| 分身框架包名黑名单 | com.bly.dkplat / com.by.chaos / com.lbe.parallel / com.excelliance.dualaid / com.lody.virtual / com.qihoo.magic |
| cgroup | cat /proc/self/cgroup |
| UID/端口 | u0_a%d + cat /proc/net/tcp6 → 0100007F: |
| 栈顶归属 | ActivityManager.getRunningTasks → topActivity 包名/类名 |
| 私有目录 | /data/data/%s + File.exists |
| 本地通道 | android.net.LocalServerSocket |

### 3.3 模拟器判定（真正生效的那一份）

文件：`smali/classes3/珂函筙…/嵋鵹躐使骩/坧肩羘隌焰罘錘睇驲朇覛.smali`（.source Utils.java）
被 LoginActivity / BaseLoginActivity / XAJDStartActivity 调用，命中 → 「不支持模拟器安装使用」+ finish。

```java
return  Build.FINGERPRINT.startsWith("generic")
     || Build.FINGERPRINT.contains("vbox")
     || Build.MODEL.contains("google_sdk")
     || Build.MODEL.contains("Emulator")
     || Build.MODEL.contains("vmos")
     || Build.SERIAL.equalsIgnoreCase("android")
     || Build.MODEL.contains("Android SDK built for x86")
     || Build.MANUFACTURER.contains("Genymotion")
     || (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
     || Build.PRODUCT.equals("google_sdk")
     || networkOperatorName.toLowerCase().equals(...)
     || SensorManager.getDefaultSensor(5)  == null   // TYPE_LIGHT
     || SensorManager.getDefaultSensor(13) == null;  // TYPE_AMBIENT_TEMPERATURE
```

**关键点**：雷电/夜神这类模拟器会把 Build 指纹伪装成真机，前 11 条通常全过；
但虚拟传感器列表里没有光线与温度传感器 → 最后两条命中。
（这也是为什么按 `ro.hardware=ttvm` 去搜搜不到：那条在未接线的 EmulatorCheckUtil 里。）

### 3.4 Frida 三重检测

| 手段 | 位置 | 细节 |
|---|---|---|
| 端口探测 | SecurityCheckUtils.躽羦鶽挴毋惛(int) | 27042 / 27047，实现落在加固壳 native `com.security.inner.apk0000.x.z` |
| 进程名 | SecurityCheckUtils.嫹欼榱殸緁鎣鰡典(Context) | getRunningServices 遍历，contains("frida")，日志 "frida检测" |
| maps 扫描 | SecurityCheckUtil.簌拗熳迺辢閶傲(String) | 读 /proc/<pid>/maps 找 .so / .jar（当前仅在死方法里被调）|

### 3.5 其他环境项（存在但部分未接线）

| 项 | 实现 | 状态 |
|---|---|---|
| root（8 条 su 路径）| SecurityCheckUtil.湛邔頥怖饲峱麶诗饔训 | 只被死方法调用 |
| 签名校验 | SecurityCheckUtil.谯胧潺塄梤僜皠紦 | 只被死方法调用 |
| 充电状态 | SecurityCheckUtil.嵋鵹躐使骩（BATTERY_CHANGED/plugged）| 只被死方法调用 |
| 无障碍服务 | AccessibilityServicesCheckUtil（accessibility_enabled / enabled_accessibility_services）| 命中引导去关闭 |

---

## 4. 运行时计量与本地判定（跑步过程中）

### 4.1 定位闸门

文件：`smali/classes3/net/crigh/cgsport/mysport_/AMAPLocationService_.smali` 与其内部类 `…$櫼螉彬彆.smali`

| # | 闸门 | 条件 | 处理 |
|---|---|---|---|
| 1 | 错误码 | getErrorCode() != 0 | 丢点 |
| 2 | 定位类型 | getLocationType() == 0 或 >= 6 | 丢点（排除缓存/无效源）|
| 3 | 精度分级 | acc<20 → 好；20≤acc<35 → 一般；≥35 → 差 | UI 提示 |
| 4 | 精度总阈值 | acc >= LocationConfig.c（默认 100）| 置定位异常 |
| 5 | 地图刷新 | 每 10 点刷一次 | 性能 |
| 6 | 起点锁 | 首个有效点固定起点 + 1 s 后启动计时/采集 | — |

### 4.2 点位数据结构（上传后会逐点复核）

```
SportLatlng(lat, lng, status, ?, timestep, lastDistance, totalDistance, lastStep, totalStep, ?, ?)
落库 SportLatLngBean: a=纬度 o=经度 v=status s=速度 t=时间戳 ac=精度 d=段距 da=累计距 st=段步 sta=累计步
```

**status 语义**：`(运动中 && !暂停中) ? 0 : 1` —— v=1 是**暂停期间打的点**，不是"被判无效"，且照样上传。

### 4.3 速度判定

- 提示文案：`txt_tips_speed_err`「系统检测到您当前速度过快，此段距离无效，请减速」；`min_speed`「当前瞬时速度较慢」
- 触发链路：AMAPLocationService_ 内部 Handler `憹釠輂鯺秋綍筴寸銧` 按 msg.what 分发（1=过快，0=过慢，4/5/6=GPS 质量）
- 后果：该段不计入里程，**点位仍然上传**（服务端能看到"被判无效的点"和原始速度）

### 4.4 必经点打卡：硬编码 60 米

文件：`AMAPLocationService_.櫼螉彬彆(List<LatLng>, lat, lng)`

```java
LatLng cur = new LatLng(lat, lng);
double d = AMapUtils.calculateLineDistance(cur, list.get(0)); // 直线距离
if (d <= 60.0) {          // 常量 0x404e000000000000，非配置项
    震动();
    命中计数++;
    已过点位串 += ";" + 命中计数;
    写入 SportBean.alreadypasspoint;
    list.remove(0);       // 顺序判定：必须依次进入
}
```

### 4.5 计步模型（室内/宿舍跑的里程是估的）

```java
v = count * 1000.0f / 2000.0f;
stepLen = (v < 1.7) ? 0.5 : (v <= 2.5 ? 0.7 : 1.1);
步数里程 += stepLen;
```

### 4.6 轨迹拟合诊断（PointTrace）

文件：`smali/classes3/珂函筙…/珂函筙/彐叐凴瀱砰漆摯.smali`（.source PointTrace.java）

- 方法：`砍欯瘵塅秅琐鮲洌([D I)[D`（最小二乘/样条求解）、`靂抋沧闌裰啻稪膕酫瘺(List)`（逐点组装 + leverage）
- 日志串：`The fit | Levarage values`；缩放常量 124.3984；窗口 b = 50
- 输入：每点的 lat/lng/status/speed/timestep/accuracy/距离/步数
- 调用点：`AMAPLocationService_$礕萻….輒岭諓滅璋儡詼(List)`，用于点位着色/重绘

leverage（杠杆值）是最小二乘里判定离群点的经典指标 —— 对"过分笔直的伪造轨迹"敏感。

### 4.7 时间维度

- 无本地防改时间：`elapsedRealtime()` 仅用于 AlarmManager 2 秒心跳
- 点位时间戳走系统时间 → 改钟会直接体现在 timestep 序列上，交由服务端比对

---

## 5. 身份与人脸

| 项 | 模型/实现 | 说明 |
|---|---|---|
| 模型 | `AuthInfos`：pointId / pointType / authType / faceImage / latlng / result / datetime / sportbeanid | 每个节点的验证记录 |
| 节点 | 起点 / 终点 / N 号点（face_start_title / face_end_title / face_way_title）| 文案在 resources |
| 抽检 | needPassPointCount（必经点）+ randomPointStr（随机点）| 上传字段 |
| 不拍 | no_take_photo_tip「…视为无效」| — |
| 活体 | 本地：libchingo_face.so + libTNN.so + libopencv_java4.so | 非纯服务端比对 |

---

## 6. 数据上传面与服务端契约

### 6.1 上传载荷 `UploadJsonSports`（33 字段）

sportId / xh / name / phoneVersion / modementMode / indoor / beginTime / endTime / activeTime / calorie /
odometer / avgSpeed / avgPace / maxSpeedPerHour / minSpeedPerHour / minuteSpeed(List) / pace(List) /
coordinate(List) / stepCount / stepMinute / lastOdometerTime / isValid / isValidReason / routeId /
planRouteName / routePolylineBh / needPassPointCount / alreadyPassPoint / alreadyPassPointResult /
randomPointStr / beganPoint / endPoint / sportImages

### 6.2 关键接口（共 144 个端点，节选）

| 动词 | 路径 | 参数 | 返回 |
|---|---|---|---|
| POST | api/l/v7/savesports | Field: jsonsports | SportResult |
| POST | api/l/v7/upload/sensorFile | Field: sportId, sensorFile | String |
| POST | api/l/v7/upload/sensorZipFile | Query: sportId, sensorZipFile | String |
| POST | api/l/v6/uploadpic | Query: xh, sportId, images | ApiResult |
| POST | api/l/v6/sports/uploadAuthInfos | Query: xh, sportId, authType, authInfos | ApiResult |
| GET | api/l/v6.1/sports/invalidconf | — | List<InvalidConfig> |
| GET | api/l/sport/tip | — | CheatTip |
| GET | api/l/v6/needUpdateSportlist | Query: xh | Object |
| GET/POST | api/l/v6.1/sports/reconsider[/save] | — / content+sportId+contact | ApiResult |

### 6.3 三个回执模型

```
SportResult   { sportId, isValid, checkStatus, inValidReason, tip }
InvalidConfig { code, reason, reasonDes }        // 服务端下发的"无效原因"码表
CheatTip      { title, content }                 // 作弊提示
```

**结论：什么算违规由服务端码表决定，客户端只做 code → 文案的展示。本地不存在"速度超过 X 判无效"的常量。**

---

## 7. 死代码清单（重要）

这些检测写了但**没有任何业务调用点**，网上流传的很多"检测点"实际上不生效：

| 实现 | 位置 | 状态 |
|---|---|---|
| CheckMockLocation（ACCESS_MOCK_LOCATION 计数 + Settings mock_location）| classes3/…/阙蔬/輬欏磞.smali | 只有自引用 |
| EmulatorCheckUtil（9 项打分 >3，含 ttvm/nox）| classes/…/秪踖拽炅鮤幕諭紨伨.smali | 只被同包 EasyProtectorLib 调用，而后者无业务调用 |
| EasyProtectorLib 島阌 / 饙旒（签名）/ 芌艖（maps）| classes/…/阙蔬.smali | 零调用 |
| SecurityCheckUtil 的 root / 签名 / 充电 / 127.0.0.1 端口 | 同上 | 只被上述死方法调用 |
| Utils.彧猊（打分制）/ 齘毊（baseband 反射）/ 骨澡（CPU intel/amd）| Utils.java | 零调用 |

---

## 8. 作弊行为 × 检测点矩阵

| 作弊行为 | 谁抓 | 证据字段 | 位置 |
|---|---|---|---|
| 模拟定位 App | 高德 SDK isFromMockProvider / MaybeMockGPSLoc / #1501 | QualityReport 上行 | classes2/com/loc/* |
| FakeLocation | SecurityCheckUtils 查包名 | 本地拦截 | classes3/…/阙蔬/伎险射筡蚓 |
| 模拟器 | Utils：Build 11 条 + 光线/温度传感器 | 登录页拦截 | classes3/…/坧肩羘隌焰罘錘睇驲朇覛 |
| 多开/分身 | VirtualApkCheckUtil 六项 | 本地拦截 | classes/…/鉩槣锉孤鋙迖执籢趬 |
| Xposed | EasyProtectorLib.猱繮滤冕 / 眽归… | 本地拦截 | classes/…/阙蔬 |
| Frida | 端口 + 进程名 + maps | 本地拦截 | classes3/…/伎险射筡蚓 |
| 调试 | isDebuggerConnected + TracerPid | 本地拦截 | classes/…/酽碶睃戉侽蘄漝 |
| 电动车/代跑 | maxSpeedPerHour / minuteSpeed / 段速超限 | coordinate.s、minuteSpeed | AMAPLocationService_ |
| 骑行伪装 | 步幅（stepCount/odometer）| stepMinute | 服务端 |
| 甩手机刷步 | 加速度计波形 → sensorFile | sensorFile/sensorZipFile | RoomSportService |
| 直线伪造轨迹 | PointTrace（leverage）+ 服务端折线偏离 | coordinate + routePolylineBh | PointTrace |
| 打卡作弊 | 60 m 顺序命中 | alreadypassPoint | AMAPLocationService_ |
| 暂停刷时长 | 暂停点 status=1 仍上传 | SportLatlng.status | AMAPLocationService_ |
| 改系统时间 | 无本地校验，timestep 序列暴露 | coordinate.t / activeTime | 服务端 |
| 代跑 | 人脸节点 + 随机抽检 | AuthInfos.result | 服务端 + libchingo_face |
| 一机多号 | phoneVersion + 多开检测 | phoneVersion | 服务端 |
| 伪造请求 | 请求 AES + 验签 | — | libAMapSDK_Location_v6_6_0.so |

---

## 9. 请求加密：伪装成高德 SDK 的 so

Java 侧（`smali/classes3/net/crigh/api/encrypt/ChingoEncrypt.smali`）：

```java
static { System.loadLibrary("AMapSDK_Location_v6_6_0"); }
public static native String cgapiAESEncrypt(String);
public static native String cgapiEnrypt(String, String);
public static native int    cgapiVerify(String, String, String, String);
```

实体验证（`lib/arm64-v8a/libAMapSDK_Location_v6_6_0.so`，1,161,192 B）：

| 检查 | 结果 |
|---|---|
| 是否真是高德 SDK | 无 "AMapLocationClient"、无 "amap" 字符串，仅 1 处 "AMap" |
| JNI 导出 | 仅 1 个：`Java_net_crigh_api_encrypt_ChingoEncrypt_cgapiEnrypt` |
| 加密实现 | 含 `AES_init_ctx_iv`（tiny-AES-c）、SHA1 |
| 对照组 | libAMapSDK_MAP_v7_4_0.so 有 165 个 Java_ 导出、65 处 AMap，是真高德 |

→ 这是典型的**白利用**（用合法 SDK 文件名承载自有加密代码），AES 密钥与验签逻辑都在 native。

---

## 10. 证据文件索引

| 内容 | 路径（相对 APK 解包根） |
|---|---|
| 采集闸门 / 逐点落库 | smali/classes3/net/crigh/cgsport/mysport_/AMAPLocationService_.smali |
| 定位回调（精度分级）| smali/classes3/net/crigh/cgsport/mysport_/AMAPLocationService_$櫼螉彬彆.smali |
| 距离/步长/绘制工作线程 | smali/classes3/net/crigh/cgsport/mysport_/AMAPLocationService_$礕萻….smali |
| 日志与消息 Handler | smali/classes3/…/軎硘鈴甉/憹釠輂鯺秋綍筴寸銧.smali |
| 阈值表 LocationConfig | smali/classes3/…/島阌酝浘崖婮踃缐耔澪節腓/亏雄開邠煱嘂咔娡葘戭.smali |
| 轨迹拟合 PointTrace | smali/classes3/…/珂函筙/彐叐凴瀱砰漆摯.smali |
| 模拟器判定（生效）| smali/classes3/…/嵋鵹躐使骩/坧肩羘隌焰罘錘睇驲朇覛.smali |
| 多开检测 | smali/classes/縰丒…/熏燵婨左崘畱噛淜/櫼螉彬彆/鉩槣锉孤鋙迖执籢趬.smali |
| 安全检测合集 | smali/classes/縰丒…/櫼螉彬彆/酽碶睃戉侽蘄漝.smali、…/阙蔬.smali |
| frida / 假定位 | smali/classes3/…/阙蔬/伎险射筡蚓.smali |
| 上传载荷 | smali/classes3/net/crigh/cgsport/model/UploadJsonSports.smali |
| 人脸模型 | smali/classes3/net/crigh/cgsport/model/AuthInfos.smali |
| 请求加密 | smali/classes3/net/crigh/api/encrypt/ChingoEncrypt.smali + lib/arm64-v8a/libAMapSDK_Location_v6_6_0.so |
| 接口全表（144 条）| api_endpoints.tsv |
| 类名映射（21,465 条）| classmap.tsv |

---

## 11. 结论

1. 这是一个**"客户端拦工具 + 服务端判行为"**的典型设计，客户端不留判定阈值，只留采集与展示。
2. 客户端最有效的三道门是：**传感器模拟器检测**、**Frida 端口/进程**、**多开包名+cgroup 组合**。
3. 数据面非常完整：**逐点速度/精度/步数 + 每分钟速度 + 每公里配速 + 传感器原始波形 + 照片 + 人脸结果**，
   足以让服务端重建整段运动过程。
4. 大量"看起来很强"的检测（root、签名、CPU 架构、baseband、评分制模拟器）在当前版本**是死代码**。
5. 请求层做了 AES + 验签，且藏在伪装的 so 里，抬高了重放/伪造门槛。

---

## 免责声明

本文仅用于移动应用安全与反作弊机制的**技术研究**，所有结论来自公开可得的 APK 静态分析。
不包含任何规避检测、伪造数据或绕过风控的方法。请勿用于违反学校规定或服务条款的用途。
