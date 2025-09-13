from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
import time

class LoginModule:
    def __init__(self, driver, username, password):
        self.driver = driver
        self.username = username
        self.password = password
        self.active = self.username is not None and self.password is not None
    
    def login_if_possible(self):
        """尝试自动识别登录表单并执行登录"""
        if not self.active:
            print('[INFO] Login module is disabled')
            return

        try:
            login_form = self._find_login_form()
            print('[INFO] Logging in...')
            # 等待页面加载
            time.sleep(2)
            
            # 填写并提交登录表单
            self._fill_and_submit_login_form(login_form)

            # 等待页面导航完成
            time.sleep(2)
        except Exception as e:
            print(f'[ERROR] Could not log in: {e}')

    def _find_login_form(self):
        """寻找页面中的登录表单"""
        forms = self.driver.find_elements(By.TAG_NAME, 'form')
        
        for form in forms:
            inputs = form.find_elements(By.TAG_NAME, 'input')

            # 筛选合适的登录表单，判断是否有密码输入框
            password_input = None
            for input_elem in inputs:
                if input_elem.get_attribute('type') == 'password':
                    password_input = input_elem
                    break

            if password_input:
                return form
        raise Exception('No login form found!')

    def _fill_and_submit_login_form(self, form):
        """填写并提交表单"""
        username_field = None
        password_field = None
        submit_btn = None

        inputs = form.find_elements(By.TAG_NAME, 'input')
        for input_elem in inputs:
            input_type = input_elem.get_attribute('type')

            # 填写用户名
            if input_type in ['text', 'email'] and username_field is None:
                input_elem.clear()  # 清除可能已填充的用户名
                input_elem.send_keys(self.username)
                username_field = input_elem
            elif input_type == 'password' and password_field is None:
                input_elem.send_keys(self.password)
                password_field = input_elem
            elif input_type == 'submit' and submit_btn is None:
                submit_btn = input_elem

        if submit_btn:
            submit_btn.click()
        else:
            form.submit()
