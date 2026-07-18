from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="docksec",
    version="2026.7.4",
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
    # Core install is scan-only (Trivy/Hadolint wrappers, reports, scoring)
    # with no LLM stack. AI analysis needs the [ai] extra.
    install_requires=[
        "pydantic>=2.13,<3",
        "python-dotenv>=1.0,<2",
        "colorama>=0.4.6,<1",
        "rich>=13.0,<16",
        "fpdf2>=2.8,<3",
        "setuptools>=65.0.0",
        "ruamel.yaml>=0.18.6",
    ],
    extras_require={
        "ai": [
            "langchain-core>=1.3,<2",
            "langchain>=1.2,<2",
            "langchain-openai>=1.2,<2",
            "langchain-anthropic>=1.4,<2",
            "langchain-google-genai>=4.2,<5",
            "langchain-ollama>=1.1,<2",
        ],
    },
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
