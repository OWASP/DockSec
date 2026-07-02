from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="docksec",
    version="2026.7.1",
    description="AI-Powered Docker Security Analyzer",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Advait Patel",
    url="https://github.com/OWASP/DockSec",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "docksec=docksec.cli:main",
        ],
    },
    project_urls={
        "Bug Tracker": "https://github.com/OWASP/DockSec/issues",
        "Documentation": "https://github.com/OWASP/DockSec/blob/main/README.md",
        "Source Code": "https://github.com/OWASP/DockSec",
    },
    python_requires=">=3.12",
    install_requires=[
        "pydantic==2.13.4",
        "langchain-core==1.3.3",
        "langchain==1.2.18",
        "langchain-openai==1.2.1",
        "langchain-anthropic==1.4.3",
        "langchain-google-genai==4.2.2",
        "langchain-ollama==1.1.0",
        "python-dotenv==1.2.2",
        "pandas==3.0.3",
        "tqdm==4.67.3",
        "colorama==0.4.6",
        "rich==15.0.0",
        "fpdf2==2.8.7",
        "tenacity==9.1.4",
        "setuptools>=65.0.0",
        "ruamel.yaml>=0.18.6",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    include_package_data=True,
    package_data={
        'docksec': ['templates/*.html'],
    },
)
