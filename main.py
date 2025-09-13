import os

# from selenium import webdriver
from seleniumwire import webdriver  # 注意：这里换成 seleniumwire

from selenium.webdriver.remote.webdriver import WebDriver

import argparse
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By

from crawl.LoginModule import LoginModule
from crawl.sensors import Sensors
from crawl.Actuators import Actuators
from crawl.Bridge import Bridge
from openai import OpenAI
from app_info.tasks import Task
# from Classes import *

# 猴子补丁，修改原始get方法，避免老超时报错导致程序终止
# 保存原始 get 方法
_original_get = WebDriver.get

# 定义静默版 get 方法
def silent_get(self, url, modify=False):
    try:
        print("nihao")
        _original_get(self, url)
        return True
    except Exception as e:  # 捕获异常对象 e
        print(f"静默失败，异常信息: {e}")  # 打印异常信息
        return False

# 替换默认的 get 方法
WebDriver.get = silent_get

parser = argparse.ArgumentParser(description='Crawler')
parser.add_argument("--url", help="Custom URL to crawl")
parser.add_argument("--username", help="Username for login")
parser.add_argument("--password", help="Password for login")

args = parser.parse_args()

# Clean form_files/dynamic
root_dirname = os.path.dirname(__file__)
dynamic_path = os.path.join(root_dirname, 'form_files', 'dynamic')
for f in os.listdir(dynamic_path):
    os.remove(os.path.join(dynamic_path, f))

def send(driver, cmd, params={}):
    return driver.execute_cdp_cmd(cmd, params)

def add_script(driver, script):
  send(driver, "Page.addScriptToEvaluateOnNewDocument", {"source": script})

WebDriver.add_script = add_script

chrome_options = webdriver.ChromeOptions()
chrome_options.add_argument("--disable-web-security")
chrome_options.add_argument("--allow-running-insecure-content")
chrome_options.add_argument("--disable-xss-auditor")
chrome_options.add_argument('--headless')

# # launch Chrome
# 配置 Chrome 浏览器的路径（可以根据需要调整）
chrome_path = os.environ.get("chrome_path")  # 从环境变量中读取
chrome_options.binary_location = chrome_path

# 创建 WebDriver 服务，自动下载并使用正确的 ChromeDriver 版本
service = Service(ChromeDriverManager().install())

# 创建 WebDriver 实例
driver = webdriver.Chrome(service=service, options=chrome_options)
# 增加页面加载超时时间（单位：秒）
driver.set_page_load_timeout(20)  # 设置为30秒

# 增加脚本执行超时时间
driver.set_script_timeout(10)

#driver.set_window_position(-1700,0)

# Read scripts and add script which will be executed when the page starts loading
## JS libraries from JaK crawler, with minor improvements
driver.add_script( open("js/lib.js", "r").read() )
driver.add_script( open("js/property_obs.js", "r").read() )
driver.add_script( open("js/md5.js", "r").read() )
driver.add_script( open("js/addeventlistener_wrapper.js", "r").read() )
driver.add_script( open("js/timing_wrapper.js", "r").read() )
driver.add_script( open("js/window_wrapper.js", "r").read() )
# Black Widow additions
driver.add_script( open("js/forms.js", "r").read() )
driver.add_script( open("js/xss_xhr.js", "r").read() )
driver.add_script( open("js/remove_alerts.js", "r").read() )


url = args.url

# # 抓包拦截模块
# def interceptor(request):

#     # 1) 修改请求头（例如加一个调试头）
#     request.headers['X-Debug'] = '1'

#     # 2) 修改 URL：示例给原 URL 增加一个查询参数 foo=bar
#     #    - 若已带 query，请自己处理拼接逻辑（下面演示稳妥做法）
#     from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

#     u = urlsplit(request.url)
#     qs = dict(parse_qsl(u.query, keep_blank_values=True))
#     qs['foo'] = 'bar'   # 这里替换为你想要的参数修改
#     new_query = urlencode(qs, doseq=True)
#     new_url = urlunsplit((u.scheme, u.netloc, u.path, new_query, u.fragment))

#     # request.url = new_url  # ✅ 直接改 URL 即可
#     request.url = "http://127.0.0.1:83/" # 验证是否拦截成功

# def interceptor_pass(request):
#     pass

# # 挂载拦截器（发送前会回调）
# driver.request_interceptor = interceptor
# driver.get(url)
# print(driver.page_source)

# driver.request_interceptor = interceptor_pass
# driver.get(url)
# print(driver.page_source)


# 主类中封装爬虫模块、应用语义图模块、漏洞模块

# 先复现爬虫模块
driver.get(url)

# 使用登录模块
login_module = LoginModule(driver, args.username, args.password)
login_module.login_if_possible()

# 核心模块初始化
sensors = Sensors(driver)
acts = Actuators(sensors)

client = OpenAI(base_url="https://api.deepseek.com")
bridge = Bridge(sensors=sensors, actuators=acts, client=client)


# task = Task(
#     task_id=1, 
#     description="Set the security level to low and test SQL injection",
#     initial_url="http://127.0.0.1:4280/index.php"
# )

# task = Task(
#     task_id=2, 
#     description="Solve CSRF in low security level",
#     initial_url="http://127.0.0.1:4280/index.php"
# )

# task = Task(
#     task_id=3, 
#     description="Set the security level to High and test SQL injection by click here to change your ID",
#     initial_url="http://127.0.0.1:4280/index.php"
# )
# 这个任务引申出怎么处理弹出新窗口的情况

# task = Task(
#     task_id=3, 
#     description="Set the security level to High and test SQL injection",
#     initial_url="http://127.0.0.1:4280/index.php"
# )

task = Task(
    task_id=4, 
    description="Set the security level to High and test SQL injection",
    initial_url="http://127.0.0.1:8080/wp-admin/"
)

bridge.run_task(task)

# 任务生成主逻辑
# 到第一个页面，遍历所有按钮，给每个网页生成初步的语义信息同时构建初始的连接图，网页的唯一标识是URL
# 任务生成Agent为各个网页生成任务
# 执行任务，执行的同时记录任务的执行元素序列以及新发现的URL，如果新URL提取出的语义信息和以前的不同，生成新任务并加入队列。

# 分析网页之间的关联性，若能关联则通过任务组合生成任务

# 网页之间的关系：跳转（有方向）；语义关联（功能上有联系且可能会影响其他的页面）










