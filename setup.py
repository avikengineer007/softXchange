from setuptools import setup, find_packages

setup(
    name="secrets-scanner",
    version="0.1.0",
    description="Deterministic, rule-based secrets scanner for uploaded packages.",
    packages=find_packages(),
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "secrets-scan=secrets_scanner.cli:main",
            "static-scan=static_analysis.cli:main",
            "scan-package=static_analysis.cli:main_combined",
        ],
    },
)
