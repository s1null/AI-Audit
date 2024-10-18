# AI-Audit
To demonstrate the capabilities of this tool, we used the code from several vulnerable code snippet repositories. These include:

https://github.com/yeswehack/vulnerable-code-snippets

https://github.com/snoopysecurity/Vulnerable-Code-Snippets

Usage:

The setup is simple to create a basic AI code scanner. We can use LM Studio (https://lmstudio.ai/) to download compatible LLMs to run locally. This will also mean that we are able to scan code on our machine even while offline.

LM Studio provides the functionality to search and download compatible LLMs within the UI, so there is no need to download models via Hugging Face. The model that is chosen should be based on the capabilities of the machine taking into consideration the GPU usage and other factors. In this circumstance we are using the deepseek-coder-v2-lite-instruct

![image](https://github.com/user-attachments/assets/466d6909-80d1-45e3-9293-0717b024e88f)

We can then start the local inference server by loading the model. The default location should be accessible at localhost:1234.

python AI-Audit.py [Code Repository] --file-types [File Extensions] (--all)

![image](https://github.com/user-attachments/assets/ee064afd-57a0-4442-96c7-9241adac55d7)

![image](https://github.com/user-attachments/assets/d8074060-1047-492f-9d01-f5fcf4948682)

![image](https://github.com/user-attachments/assets/403320cc-47c9-4c33-b97e-2a4004326d2e)
