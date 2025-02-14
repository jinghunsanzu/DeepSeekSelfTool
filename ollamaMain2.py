import os
import re
import json
import requests
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import QApplication
from config import OLLAMA_API_URL, OLLAMA_MODEL  # 用户自定义配置


class CyberTextEdit(QtWidgets.QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            QTextEdit {
                background-color: #001a1a;
                color: #00ff00;
                border: 2px solid #00ffff;
                border-radius: 5px;
                padding: 10px;
                font-family: 'Consolas';
                font-size: 12pt;
            }
        """)


class HackerWorker(QThread):
    analysis_complete = pyqtSignal(str)
    progress_update = pyqtSignal(str)

    def __init__(self, files_content):
        super().__init__()
        self.files_content = files_content

    def run(self):
        full_report = []
        for filepath, content in self.files_content.items():
            self.progress_update.emit(f"🔍 Analyzing {os.path.basename(filepath)}...")

            prompt = f"""【强制指令】你是一个专业的安全审计AI，请按以下要求分析代码：

1. 漏洞分析流程：
   1.1 识别潜在风险点（SQL操作、文件操作、用户输入点、文件上传漏洞、CSRF、SSRF、XSS、RCE、OWASP top10等漏洞）
   1.2 验证漏洞可利用性
   1.3 按CVSS评分标准评估风险等级

2. 输出规则：
   - 仅输出确认存在的高危/中危漏洞
   - 使用严格格式：[风险等级] 类型 - 位置:行号 - 50字内描述
   - 禁止解释漏洞原理
   - 禁止给出修复建议
   - 如果有可能，给出POC（HTTP请求数据包）

3. 输出示例（除此外不要有任何输出）：
   [高危] SQL注入 - user_login.php:32 - 未过滤的$_GET参数直接拼接SQL查询
   [POC]POST /login.php HTTP/1.1
   Host: example.com
   Content-Type: application/x-www-form-urlencoded
   [中危] XSS - comment.jsp:15 - 未转义的userInput输出到HTML
   [POC]POST /login.php HTTP/1.1
   Host: example.com
   Content-Type: application/x-www-form-urlencoded

4. 当前代码（仅限分析）：
{content[:3000]}"""
            try:
                response = requests.post(
                    f"{OLLAMA_API_URL}/api/generate",
                    json={
                        "model": OLLAMA_MODEL,
                        "prompt": prompt,
                        "stream": False
                    }
                )
                result = json.loads(response.text)["response"]
                result = re.sub(r'<think>.*?</think>', '', result, flags=re.DOTALL)
                full_report.append(f"📄 文件：{filepath}\n{result}\n{'━' * 50}")
            except Exception as e:
                full_report.append(f"❌ 错误：处理文件 {filepath} 时发生错误\n{str(e)}")

        self.analysis_complete.emit("\n".join(full_report))


class WebshellWorker(QThread):
    detection_complete = pyqtSignal(str)
    progress_update = pyqtSignal(str)

    def __init__(self, files_content):
        super().__init__()
        self.files_content = files_content

    def run(self):
        detection_results = []
        for filepath, content in self.files_content.items():
            self.progress_update.emit(f"🕵️ 扫描 {os.path.basename(filepath)}...")

            prompt = f"""【Webshell检测指令】请严格按以下步骤分析代码：

1. 检测要求：         
    请分析以下文件内容是否为WebShell或内存马。要求：
    1. 检查PHP/JSP/ASP等WebShell特征（如加密函数、执行系统命令、文件操作）
    2. 识别内存马特征（如无文件落地、进程注入、异常网络连接）
    3. 分析代码中的可疑功能（如命令执行、文件上传、信息收集）
    4. 检查混淆编码、加密手段等规避技术

2. 判断规则：
   - 仅当确认恶意性时报告
   - 输出格式：🔴 [高危] Webshell - 文件名:行号 - 检测到[特征1+特征2+...]

3. 输出示例（严格按照此格式输出，不要有任何的补充，如果未检测到危险，则不输出，除此之外，不要有任何输出）：
   🔴 [高危] Webshell - malicious.php:8 - 检测到[system执行+base64解码+错误抑制]

4. 待分析代码：
{content[:3000]}"""

            try:
                response = requests.post(
                    f"{OLLAMA_API_URL}/api/generate",
                    json={
                        "model": OLLAMA_MODEL,
                        "prompt": prompt,
                        "stream": False
                    }
                )
                result = json.loads(response.text)["response"]
                result = re.sub(r'<think>.*?</think>', '', result, flags=re.DOTALL)
                detection_results.append(f"📁 {filepath}\n{result}\n{'━' * 50}")
            except Exception as e:
                detection_results.append(f"❌ 错误：{filepath}\n{str(e)}")

        self.detection_complete.emit("\n".join(detection_results))


class CyberScanner(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("安全分析平台 ")
        self.setGeometry(100, 100, 1280, 720)
        self.setup_ui()
        self.files_content = {}
        self.scan_thread = None

    def setup_ui(self):
        main_widget = QtWidgets.QWidget()
        self.setCentralWidget(main_widget)
        layout = QtWidgets.QHBoxLayout(main_widget)

        # 左侧面板
        left_panel = QtWidgets.QFrame()
        left_panel.setStyleSheet("background-color: #000d1a; border-right: 2px solid #00ffff;")
        left_layout = QtWidgets.QVBoxLayout(left_panel)

        # 目录选择按钮
        self.btn_select = QtWidgets.QPushButton("📁 激活数据源")
        self.btn_select.setStyleSheet("""
            QPushButton {
                background-color: #002b2b;
                color: #00ffff;
                border: 2px solid #008080;
                padding: 12px;
                font-size: 14pt;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #004d4d;
                border-color: #00ffff;
            }
        """)
        self.btn_select.clicked.connect(self.select_directory)
        left_layout.addWidget(self.btn_select)

        # 路径显示
        self.lbl_path = QtWidgets.QLabel("未选择数据源")
        self.lbl_path.setStyleSheet("color: #00ff00; font-size: 10pt; padding: 5px;")
        left_layout.addWidget(self.lbl_path)

        # 模式选择
        mode_group = QtWidgets.QGroupBox("🔧 检测模式")
        mode_group.setStyleSheet("""
            QGroupBox {
                color: #00ff00;
                border: 1px solid #00ffff;
                margin-top: 10px;
                font-size: 12pt;
            }
        """)
        mode_layout = QtWidgets.QVBoxLayout()
        self.radio_audit = QtWidgets.QRadioButton("代码安全审计")
        self.radio_webshell = QtWidgets.QRadioButton("Webshell检测")
        self.radio_audit.setChecked(True)
        for rb in [self.radio_audit, self.radio_webshell]:
            rb.setStyleSheet("""
                QRadioButton { color: #00ff00; padding: 8px; }
                QRadioButton::indicator { width: 20px; height: 20px; }
            """)
            mode_layout.addWidget(rb)
        mode_group.setLayout(mode_layout)
        left_layout.addWidget(mode_group)

        # 新增：是否审计 JavaScript 文件的复选框
        self.checkbox_audit_js = QtWidgets.QCheckBox("审计 静态 文件")
        self.checkbox_audit_js.setChecked(True)  # 默认选中
        self.checkbox_audit_js.setStyleSheet("""
            QCheckBox { color: #00ff00; padding: 8px; }
            QCheckBox::indicator { width: 20px; height: 20px; }
        """)
        left_layout.addWidget(self.checkbox_audit_js)

        # 文件树
        self.file_tree = QtWidgets.QTreeView()
        self.file_model = QtWidgets.QFileSystemModel()
        self.file_model.setRootPath("")
        self.file_tree.setModel(self.file_model)
        self.file_tree.setStyleSheet("""
            QTreeView {
                background-color: #001a1a;
                color: #00ff00;
                border: 1px solid #008080;
                font-family: 'Consolas';
            }
            QTreeView::item:hover { background-color: #003333; }
        """)
        left_layout.addWidget(self.file_tree)

        # 扫描按钮
        self.btn_scan = QtWidgets.QPushButton("🚨 启动扫描协议")
        self.btn_scan.setStyleSheet("""
            QPushButton {
                background-color: #004d4d;
                color: #00ffff;
                border: 2px solid #00ffff;
                padding: 15px;
                font-size: 16pt;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:disabled { 
                background-color: #002b2b;
                color: #008080;
                border-color: #004d4d;
            }
            QPushButton:hover { background-color: #006666; }
        """)
        self.btn_scan.clicked.connect(self.start_scan)
        self.btn_scan.setEnabled(False)
        left_layout.addWidget(self.btn_scan)

        # 右侧显示区
        self.result_display = CyberTextEdit()
        self.result_display.setAcceptRichText(True)

        layout.addWidget(left_panel, 1)
        layout.addWidget(self.result_display, 2)

        # 状态栏
        self.status_bar = QtWidgets.QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.setStyleSheet("""
            QStatusBar {
                background-color: #000d1a;
                color: #00ff00;
                border-top: 1px solid #00ffff;
                font-family: 'Consolas';
            }
        """)

    def select_directory(self):
        directory = QtWidgets.QFileDialog.getExistingDirectory(
            self,
            "选择代码矩阵接入点",
            "",
            QtWidgets.QFileDialog.ShowDirsOnly
        )
        if directory:
            self.lbl_path.setText(f"📂 数据源：{directory}")
            self.file_tree.setRootIndex(self.file_model.index(directory))
            self.btn_scan.setEnabled(True)
            self.status_bar.showMessage("✅ 数据源接入成功")

    def start_scan(self):
        root_index = self.file_tree.rootIndex()
        if not root_index.isValid():
            QtWidgets.QMessageBox.warning(self, "警告", "请先选择代码目录！")
            return

        root_path = self.file_model.filePath(root_index)
        self.files_content = self.scan_code_files(root_path)

        if self.radio_audit.isChecked():
            worker = HackerWorker(self.files_content)
            init_msg = "🚀 启动深度代码分析协议..."
            complete_signal = worker.analysis_complete
        else:
            worker = WebshellWorker(self.files_content)
            init_msg = "🕵️ 启动Webshell检测协议..."
            complete_signal = worker.detection_complete

        self.scan_thread = worker
        self.scan_thread.progress_update.connect(self.update_status)
        complete_signal.connect(self.show_results)
        self.scan_thread.start()

        self.btn_scan.setEnabled(False)
        self.result_display.setText(f"{init_msg}\n" + "▮" * 50 + "\n")

    def scan_code_files(self, directory):
        allowed_ext = ['.php', '.jsp', '.asp', '.js', '.html', '.py', '.java']

        # 如果用户选择不审计 静态 文件，则从允许的扩展名中移除 .js
        if not self.checkbox_audit_js.isChecked():
            allowed_ext.remove('.js')
            allowed_ext.remove('.html')

        code_files = {}

        for root, _, files in os.walk(directory):
            for file in files:
                if os.path.splitext(file)[1].lower() in allowed_ext:
                    path = os.path.join(root, file)
                    try:
                        with open(path, 'r', encoding='utf-8') as f:
                            code_files[path] = f.read()
                    except:
                        code_files[path] = "无法读取文件内容"
        return code_files

    def update_status(self, message):
        self.status_bar.showMessage(message)
        self.result_display.append(f"⚡ {message}")

    def show_results(self, report):
        self.btn_scan.setEnabled(True)

        if self.radio_webshell.isChecked():
            self.result_display.append("\n🔍 Webshell检测完成！结果如下：\n")
            report = re.sub(r'🔴 \[高危\]', '🔴 [高危]', report)
            report = re.sub(r'✅ \[安全\]', '✅ [安全]', report)
        else:
            self.result_display.append("\n🔥 代码审计完成！发现以下安全漏洞：\n")
            report = re.sub(r'\[高危\]', '[高危]', report)
            report = re.sub(r'\[中危\]', '[中危]', report)

        self.result_display.append(report)
        self.status_bar.showMessage("✅ 扫描完成")


if __name__ == "__main__":
    OLLAMA_HOST = OLLAMA_API_URL.split('/api')[0]

    app = QtWidgets.QApplication([])
    app.setStyle('Fusion')

    font = QtGui.QFont("Consolas", 10)
    app.setFont(font)

    window = CyberScanner()
    window.show()
    app.exec_()
