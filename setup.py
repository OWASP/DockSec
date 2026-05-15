from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="docksec",
    version="2026.5.6",
    description="AI-Powered Docker Security Analyzer",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Advait Patel",
    url="https://github.com/advaitpatel/DockSec",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "docksec=docksec.cli:main",
        ],
    },
    project_urls={
        "Bug Tracker": "https://github.com/advaitpatel/DockSec/issues",
        "Documentation": "https://github.com/advaitpatel/DockSec/blob/main/README.md",
        "Source Code": "https://github.com/advaitpatel/DockSec",
    },
    python_requires=">=3.12",
    install_requires=[
        "pydantic==2.13.4",
        "langchain-core==0.3.26",
        "langchain==0.3.13",
        "langchain-openai==0.2.10",
        "langchain-anthropic==0.3.0",
        "langchain-google-genai==2.0.5",
        "langchain-ollama==0.2.0",
        "python-dotenv==1.2.2",
        "pandas==3.0.2",
        "tqdm==4.67.3",
        "colorama==0.4.6",
        "rich==15.0.0",
        "fpdf2==2.8.7",
        "tenacity==9.1.4",
        "setuptools>=65.0.0",
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
