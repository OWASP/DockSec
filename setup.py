from setuptools import setup, find_packages

setup(
    name="docksec",
    version="2026.5.6",
    description="AI-Powered Docker Security Analyzer",
    long_description=open("README.md").read(),
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
        "pydantic==2.10.3",
        "langchain-core==1.3.3",
        "langchain==1.2.18",
        "langchain-openai==1.2.1",
        "langchain-anthropic==1.4.3",
        "langchain-google-genai==4.2.2",
        "langchain-ollama==1.1.0",
        "python-dotenv==1.0.1",
        "pandas==2.2.3",
        "tqdm==4.67.1",
        "colorama==0.4.6",
        "rich==13.9.4",
        "fpdf2==2.8.1",
        "tenacity==9.0.0",
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
